//-----------------------------------------------------------------------------
//
//  Copyright (C) 2010-2012 Artem Rodygin
//
//  This file is part of EncMQ.
//
//  EncMQ is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  EncMQ is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with EncMQ.  If not, see <http://www.gnu.org/licenses/>.
//
//-----------------------------------------------------------------------------

/** @file encmq/src/client.cc
 * Contains implementation of class "encmq::client".
 * @author Artem Rodygin
 */

#include <encmq.h>
#include <internal.h>

// ZeroMQ
#include <zmq.h>

// Protocol Buffers
#include <google/protobuf/message.h>
#include <message.pb.h>

// C++ Logging Library
#include <log4cplus/logger.h>

// OpenSSL
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

// Standard C/C++ Libraries
#include <cstdio>
#include <cstdlib>
#include <cstring>

//-----------------------------------------------------------------------------
//  Implementation of class "encmq::client".
//-----------------------------------------------------------------------------

namespace encmq
{

using std::string;
using google::protobuf::Message;

//-----------------------------------------------------------------------------
//  Constructors/destructors.
//-----------------------------------------------------------------------------

/**
 * Connects to the specified server.
 *
 * @throw encmq::exception ENCMQ_ERROR_SSL_RSA - error on RSA key retrieval.
 * @throw encmq::exception ENCMQ_ERROR_SSL_AES - error on symmetric key generation.
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN - unknown error.
 */
client::client (const char * addr,      /**< [in] Address of the server (e.g. "127.0.0.1").                         */
                int          port,      /**< [in] Port of the server.                                               */
                const char * keyfile)   /**< [in] Path to file with public RSA key (NULL means disable encryption). */
  : node(ZMQ_REQ, addr, port),
    m_rsa(NULL),
    m_key(NULL)
{
    LOG4CPLUS_TRACE(logger, "[encmq::client::client] ENTER");
    LOG4CPLUS_TRACE(logger, "[encmq::client::client] keyfile = " << (keyfile == NULL ? "NULL" : keyfile));

    if (keyfile != NULL)
    {
        m_rsa = RSA_new();

        try
        {
            // retrieve RSA public key
            FILE * fp = fopen(keyfile, "r");

            if (fp == NULL)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            if (PEM_read_RSAPublicKey(fp, &m_rsa, NULL, NULL) == 0)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            fclose(fp);

            // generate symmetric key for cipher
            m_key = (unsigned char *) malloc(EVP_MAX_KEY_LENGTH);
            memset(m_key, 0, EVP_MAX_KEY_LENGTH);

            EVP_CIPHER_CTX_init(&m_ctx);

            if (EVP_EncryptInit_ex(&m_ctx, EVP_aes_128_ofb(), NULL, NULL, NULL) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_CIPHER_CTX_rand_key(&m_ctx, m_key) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);
        }
        catch (...)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::client::client] " << get_ssl_error());
            RSA_free(m_rsa);
            throw;
        }
    }

    LOG4CPLUS_TRACE(logger, "[encmq::client::client] EXIT");
}

/**
 * Releases taken system resources.
 */
client::~client ()
{
    LOG4CPLUS_TRACE(logger, "[encmq::client::~client] ENTER");

    if (m_key != NULL)
    {
        EVP_CIPHER_CTX_cleanup(&m_ctx);
        free(m_key);
    }

    if (m_rsa != NULL)
    {
        RSA_free(m_rsa);
    }

    LOG4CPLUS_TRACE(logger, "[encmq::client::~client] EXIT");
}

//-----------------------------------------------------------------------------
//  Public interface.
//-----------------------------------------------------------------------------

/**
 * Sends specified message.
 *
 * @return true  - the message was successfully sent.
 * @return false - the message cannot be sent at the moment (in non-blocking mode only).
 *
// * @throw encmq::exception ENCMQ_ERROR_SSL_RSA - error on symmetric key encryption.
 * @throw encmq::exception ENCMQ_ERROR_SSL_AES - error on message encryption.
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN - unknown error.
 */
bool client::send (const Message * msg,     /**< [in] Message to be sent.                            */
                   bool            block)   /**< [in] Whether to block thread until message is sent. */
{
    LOG4CPLUS_TRACE(logger, "[encmq::client::send] ENTER");

    return node::send(msg, block);
}

/**
 * Receives new expected message.
 *
 * @return true  - new message was successfully received.
 * @return false - there is no message available at the moment (in non-blocking mode only).
 *
 * @throw encmq::exception ENCMQ_ERROR_WRONG_MESSAGE - type of a message is not as expected.
 * @throw encmq::exception ENCMQ_ERROR_WRONG_MAC     - MAC of a message is not as expected.
 * @throw encmq::exception ENCMQ_ERROR_SSL_AES       - error on message decryption.
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN       - unknown error.
 */
bool client::receive (Message * msg,    /**< [out] Received message.                                  */
                      bool      block)  /**< [in]  Whether to block thread until message is received. */
{
    LOG4CPLUS_TRACE(logger, "[encmq::client::receive] ENTER (expected)");

    if (!node::receive(msg, block))
    {
        LOG4CPLUS_TRACE(logger, "[encmq::client::receive] EXIT = false");
        return false;
    }

    LOG4CPLUS_TRACE(logger, "[encmq::client::receive] EXIT = true");
    return true;
}

/**
 * Receives new unknown message.
 * The message is created dynamically, and it is caller's responsibility to free allocated memory when done.
 *
 * @return Pointer to the new message if it was successfully received, or
 *         NULL if there is no message available at the moment (in non-blocking mode only).
 *
 * @throw encmq::exception ENCMQ_ERROR_WRONG_MAC - MAC of a message is not as expected.
 * @throw encmq::exception ENCMQ_ERROR_SSL_AES   - error on message decryption.
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN   - unknown error.
 */
Message * client::receive (bool block)  /**< [in] Whether to block thread until message is received. */
{
    LOG4CPLUS_TRACE(logger, "[encmq::client::receive] ENTER (unknown)");

    return node::receive(block);
}

//-----------------------------------------------------------------------------
//  Protected interface.
//-----------------------------------------------------------------------------

/**
 * Puts client's symmetric key to the envelope.
 *
 * @param [in] msg Pointer to the envelope just prepared for sending.
 * @return true  - success.
 * @return false - failure.
 */
bool client::before_send (Message * msg)
{
    LOG4CPLUS_TRACE(logger, "[encmq::client::before_send] ENTER");

    if (m_key != NULL)
    {
        message::envelope * envelope = (message::envelope *) msg;

        // encrypt client's symmetric key
        string buf(RSA_size(m_rsa), '\0');

        if (RSA_public_encrypt(EVP_MAX_KEY_LENGTH, m_key, (unsigned char *) buf.c_str(), m_rsa, ENCMQ_RSA_PADDING) == -1)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::client::before_send] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::client::before_send] EXIT = false");
            return false;
        }

        // serialize encrypted client's symmetric key
        string key(buf.c_str(), buf.size());
        envelope->SetExtension(message::key, key);
    }

    LOG4CPLUS_TRACE(logger, "[encmq::client::before_send] EXIT = true");
    return true;
}

/**
 * Stub implementation.
 *
 * @return Always true.
 */
bool client::after_receive (Message *)
{
    return true;
}

/**
 * Encrypts serialized message.
 *
 * @param [in] msg_data Custom serialized message.
 * @param [in] msg_size Size of the serialized message.
 * @return true  - message was successfully encrypted.
 * @return false - error is occured.
 */
bool client::encrypt (unsigned char * msg_data, int msg_size)
{
    LOG4CPLUS_TRACE(logger, "[encmq::client::encrypt] ENTER");

    if (m_key != NULL)
    {
        int num;

        if (EVP_EncryptInit_ex(&m_ctx, EVP_aes_128_ofb(), NULL, m_key, NULL) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::client::encrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::client::encrypt] EXIT = false");
            return false;
        }

        if (EVP_EncryptUpdate(&m_ctx, msg_data, &num, msg_data, msg_size) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::client::encrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::client::encrypt] EXIT = false");
            return false;
        }

        if (EVP_EncryptFinal_ex(&m_ctx, msg_data, &num) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::client::encrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::client::encrypt] EXIT = false");
            return false;
        }
    }

    LOG4CPLUS_TRACE(logger, "[encmq::client::encrypt] EXIT = true");
    return true;
}

/**
 * Decrypts serialized message.
 *
 * @param [in] msg_data Custom serialized message.
 * @param [in] msg_size Size of the serialized message.
 * @return true  - message was successfully decrypted.
 * @return false - error is occured.
 */
bool client::decrypt (unsigned char * msg_data, int msg_size)
{
    LOG4CPLUS_TRACE(logger, "[encmq::client::decrypt] ENTER");

    if (m_key != NULL)
    {
        int num;

        if (EVP_DecryptInit_ex(&m_ctx, EVP_aes_128_ofb(), NULL, m_key, NULL) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::client::decrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::client::decrypt] EXIT = false");
            return false;
        }

        if (EVP_DecryptUpdate(&m_ctx, msg_data, &num, msg_data, msg_size) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::client::decrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::client::decrypt] EXIT = false");
            return false;
        }

        if (EVP_DecryptFinal_ex(&m_ctx, msg_data, &num) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::client::decrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::client::decrypt] EXIT = false");
            return false;
        }
    }

    LOG4CPLUS_TRACE(logger, "[encmq::client::decrypt] EXIT = true");
    return true;
}

}
