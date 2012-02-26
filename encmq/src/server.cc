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

/** @file encmq/src/server.cc
 * Contains implementation of class "encmq::server".
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
//  Implementation of class "encmq::server".
//-----------------------------------------------------------------------------

namespace encmq
{

using std::string;
using google::protobuf::Message;

//-----------------------------------------------------------------------------
//  Constructors/destructors.
//-----------------------------------------------------------------------------

/**
 * Binds the server to specified network interface.
 *
 * @throw encmq::exception ENCMQ_ERROR_ADDR_IN_USE    - the given interface is already in use.
 * @throw encmq::exception ENCMQ_ERROR_ADDR_NOT_FOUND - a nonexistent interface was requested.
 * @throw encmq::exception ENCMQ_ERROR_SSL_RSA        - RSA key error.
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN        - unknown error.
 */
server::server (const char * addr,      /**< [in] Interface to bind (e.g. "eth0"). */
                int          port,      /**< [in] Port to bind.                    */
                const char * keyfile)   /**< [in] Path to file with private key.   */
  : node(ZMQ_REP, addr, port),
    m_rsa(RSA_new()),
    m_key(NULL),
    use_key(false)
{
    assert(keyfile != NULL);

    LOG4CPLUS_TRACE(logger, "[encmq::server::server] ENTER");
    LOG4CPLUS_TRACE(logger, "[encmq::server::server] keyfile = " << keyfile);

    EVP_CIPHER_CTX_init(&m_ctx);

    // retrieve RSA private key
    try
    {
        FILE * fp = fopen(keyfile, "r");

        if (fp == NULL)
        throw exception(ENCMQ_ERROR_SSL_RSA);

        if (PEM_read_RSAPrivateKey(fp, &m_rsa, NULL, NULL) == 0)
        throw exception(ENCMQ_ERROR_SSL_RSA);

        if (RSA_check_key(m_rsa) == 0)
        throw exception(ENCMQ_ERROR_SSL_RSA);

        fclose(fp);
    }
    catch (...)
    {
        LOG4CPLUS_ERROR(logger, "[encmq::server::server] " << get_ssl_error());
        RSA_free(m_rsa);
        throw;
    }

    // prepare storage for client's symmetric key
    m_key = (unsigned char *) malloc(EVP_MAX_KEY_LENGTH);
    memset(m_key, 0, EVP_MAX_KEY_LENGTH);

    LOG4CPLUS_TRACE(logger, "[encmq::server::server] EXIT");
}

/**
 * Releases taken system resources.
 */
server::~server ()
{
    LOG4CPLUS_TRACE(logger, "[encmq::server::~server] ENTER");

    EVP_CIPHER_CTX_cleanup(&m_ctx);

    if (m_key != NULL)
    {
        free(m_key);
    }

    if (m_rsa != NULL)
    {
        RSA_free(m_rsa);
    }

    LOG4CPLUS_TRACE(logger, "[encmq::server::~server] EXIT");
}

//--------------------------------------------------------------------------------------------------
//  Public interface.
//--------------------------------------------------------------------------------------------------

/**
 * Sends specified message.
 *
 * @return true  - the message was successfully sent.
 * @return false - the message cannot be sent at the moment (in non-blocking mode only).
 *
 * @throw encmq::exception ENCMQ_ERROR_SSL_AES - error on message encryption.
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN - unknown error.
 */
bool server::send (const Message * msg,     /**< [in] Message to be sent.                            */
                   bool            block)   /**< [in] Whether to block thread until message is sent. */
{
    LOG4CPLUS_TRACE(logger, "[encmq::server::send] ENTER");

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
 * @throw encmq::exception ENCMQ_ERROR_SSL_RSA       - error on symmetric key decryption.
 * @throw encmq::exception ENCMQ_ERROR_SSL_AES       - error on message decryption.
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN       - unknown error.
 */
bool server::receive (Message * msg,    /**< [out] Received message.                                  */
                      bool      block)  /**< [in]  Whether to block thread until message is received. */
{
    LOG4CPLUS_TRACE(logger, "[encmq::server::receive] ENTER (expected)");

    if (!node::receive(msg, block))
    {
        LOG4CPLUS_TRACE(logger, "[encmq::server::receive] EXIT = false");
        return false;
    }

    LOG4CPLUS_TRACE(logger, "[encmq::server::receive] EXIT = true");
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
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN   - unknown error.
 */
Message * server::receive (bool block)  /**< [in] Whether to block thread until message is received. */
{
    LOG4CPLUS_TRACE(logger, "[encmq::server::receive] ENTER (unknown)");

    return node::receive(block);
}

//-----------------------------------------------------------------------------
//  Protected interface.
//-----------------------------------------------------------------------------

/**
 * Stub implementation.
 *
 * @return Always true.
 */
bool server::before_send (Message *)
{
    return true;
}

/**
 * Retrieves client's symmetric key from the envelope.
 *
 * @param [in] msg Pointer to the just received envelope.
 * @return true  - success.
 * @return false - failure.
 */
bool server::after_receive (Message * msg)
{
    LOG4CPLUS_TRACE(logger, "[encmq::server::after_receive] ENTER");

    message::envelope * envelope = (message::envelope *) msg;

    use_key = envelope->HasExtension(message::key);

    if (use_key)
    {
        // retrieve encrypted client's symmetric key
        string key = envelope->GetExtension(message::key);

        // decrypt client's symmetric key
        if (RSA_private_decrypt(key.size(), (unsigned char *) key.c_str(), m_key, m_rsa, ENCMQ_RSA_PADDING) == -1)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::after_receive] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::server::after_receive] EXIT = false");
            return false;
        }
    }

    LOG4CPLUS_TRACE(logger, "[encmq::server::after_receive] EXIT = true");
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
bool server::encrypt (unsigned char * msg_data, int msg_size)
{
    LOG4CPLUS_TRACE(logger, "[encmq::server::encrypt] ENTER");

    if (use_key)
    {
        int num;

        if (EVP_EncryptInit_ex(&m_ctx, EVP_aes_128_ofb(), NULL, m_key, NULL) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::encrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::server::encrypt] EXIT = false");
            return false;
        }

        if (EVP_EncryptUpdate(&m_ctx, msg_data, &num, msg_data, msg_size) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::encrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::server::encrypt] EXIT = false");
            return false;
        }

        if (EVP_EncryptFinal_ex(&m_ctx, msg_data, &num) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::encrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::server::encrypt] EXIT = false");
            return false;
        }

        use_key = false;
    }

    LOG4CPLUS_TRACE(logger, "[encmq::server::encrypt] EXIT = true");
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
bool server::decrypt (unsigned char * msg_data, int msg_size)
{
    LOG4CPLUS_TRACE(logger, "[encmq::server::decrypt] ENTER");

    if (use_key)
    {
        int num;

        if (EVP_DecryptInit_ex(&m_ctx, EVP_aes_128_ofb(), NULL, m_key, NULL) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::decrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::server::decrypt] EXIT = false");
            return false;
        }

        if (EVP_DecryptUpdate(&m_ctx, msg_data, &num, msg_data, msg_size) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::decrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::server::decrypt] EXIT = false");
            return false;
        }

        if (EVP_DecryptFinal_ex(&m_ctx, msg_data, &num) == 0)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::decrypt] " << get_ssl_error());
            LOG4CPLUS_TRACE(logger, "[encmq::server::decrypt] EXIT = false");
            return false;
        }
    }

    LOG4CPLUS_TRACE(logger, "[encmq::server::decrypt] EXIT = true");
    return true;
}

}
