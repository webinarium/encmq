//-----------------------------------------------------------------------------
//
//  Copyright (C) 2010-2011 Artem Rodygin
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

// Message definitions
#include <message.pb.h>

// ZeroMQ
#include <zmq.h>

// Protocol Buffers
#include <google/protobuf/message.h>
#include <google/protobuf/descriptor.h>

// C++ Logging Library
#include <log4cplus/logger.h>

// OpenSSL
#include <openssl/bio.h>
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
using google::protobuf::MessageFactory;
using google::protobuf::Descriptor;
using google::protobuf::DescriptorPool;

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
client::client (const char * addr,      /**< [in] Address of the server (e.g. "127.0.0.1").                          */
                int          port,      /**< [in] Port of the server.                                                */
                bool         cipher,    /**< [in] Whether to encrypt traffic.                                        */
                const char * keyfile)   /**< [in] Path to file with public RSA key (ignored when 'cipher' is false). */
  : node(ZMQ_REQ, addr, port),
    m_key(NULL),
    m_pubkey(NULL)
{
    LOG4CPLUS_TRACE(logger, "[encmq::client::client] ENTER");
    LOG4CPLUS_TRACE(logger, "[encmq::client::client] cipher  = " << cipher);
    LOG4CPLUS_TRACE(logger, "[encmq::client::client] keyfile = " << (keyfile == NULL ? "NULL" : keyfile));

    if (cipher)
    {
        m_pubkey = RSA_new();

        try
        {
            // retrieve RSA public key
            if (keyfile == NULL)
            {
                LOG4CPLUS_TRACE(logger, "[encmq::client::client] Request server for RSA public key.");

                message::rsa_hello rsa_hello;
                message::rsa_key   rsa_key;

                this->send(&rsa_hello, true);
                node::receive(&rsa_key, true);

                if (rsa_key.key_size() == 0)
                throw exception(ENCMQ_ERROR_SSL_RSA);

                BIO * mem = BIO_new(BIO_s_mem());
                BIO_write(mem, rsa_key.key_data().c_str(), rsa_key.key_size());

                if (PEM_read_bio_RSAPublicKey(mem, &m_pubkey, NULL, NULL) == 0)
                throw exception(ENCMQ_ERROR_SSL_RSA);

                BIO_free(mem);
            }
            else
            {
                LOG4CPLUS_TRACE(logger, "[encmq::client::client] Load RSA public key from file.");

                FILE * fp = fopen(keyfile, "r");

                if (fp == NULL)
                throw exception(ENCMQ_ERROR_SSL_RSA);

                if (PEM_read_RSAPublicKey(fp, &m_pubkey, NULL, NULL) == 0)
                throw exception(ENCMQ_ERROR_SSL_RSA);

                fclose(fp);
            }

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
            RSA_free(m_pubkey);
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

    if (m_pubkey != NULL)
    {
        RSA_free(m_pubkey);
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
 * @throw encmq::exception ENCMQ_ERROR_SSL_RSA - error on symmetric key encryption.
 * @throw encmq::exception ENCMQ_ERROR_SSL_AES - error on message encryption.
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN - unknown error.
 */
bool client::send (const Message * msg,     /**< [in] Message to be sent.                            */
                   bool            block)   /**< [in] Whether to block thread until message is sent. */
{
    LOG4CPLUS_TRACE(logger, "[encmq::client::send] ENTER");

    assert(msg != NULL);

    // envelope of request
    message::request request;

    // serialize message for the envelope
    string str;
    msg->SerializeToString(&str);

    // put MAC and client's key to the envelope
    if (m_key == NULL)
    {
        LOG4CPLUS_TRACE(logger, "[encmq::client::send] Encryption is disabled.");

        request.set_key_size(0);
        request.set_mac_size(0);
    }
    else
    {
        LOG4CPLUS_TRACE(logger, "[encmq::client::send] Encryption is enabled.");

        try
        {
            // encrypt client's symmetric key
            string buf(RSA_size(m_pubkey), '\0');

            if (RSA_public_encrypt(EVP_MAX_KEY_LENGTH, m_key, (unsigned char *) buf.c_str(), m_pubkey, ENCMQ_RSA_PADDING) == -1)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            // serialize encrypted client's symmetric key
            request.set_key_size(buf.size());
            request.set_key_data(buf.c_str(), buf.size());

            // add MAC to the message
            string mac = generate_mac(str);

            request.set_mac_size(mac.size());
            request.set_mac_data(mac.c_str(), mac.size());

            // encrypt serialized message
            int num;
            unsigned char * ptr = (unsigned char *) str.c_str();

            if (EVP_EncryptInit_ex(&m_ctx, EVP_aes_128_ofb(), NULL, m_key, NULL) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_EncryptUpdate(&m_ctx, ptr, &num, ptr, str.size()) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_EncryptFinal_ex(&m_ctx, ptr, &num) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);
        }
        catch (...)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::client::send] " << get_ssl_error());
            throw;
        }
    }

    // put serialized message to the envelope
    request.set_msg_type(msg->GetDescriptor()->full_name());
    request.set_msg_size(str.size());
    request.set_msg_data(str.c_str(), str.size());

    // send the envelope
    return node::send(&request, block);
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

    assert(msg != NULL);

    // envelope of reply
    message::reply reply;

    // receive the envelope
    if (!node::receive(&reply, block))
    {
        LOG4CPLUS_TRACE(logger, "[encmq::client::receive] EXIT = false");
        return false;
    }

    // check message type descriptor
    if (msg->GetDescriptor()->full_name() != reply.msg_type())
    {
        LOG4CPLUS_WARN(logger, "[encmq::client::receive] Received message type is not as expected.");
        throw exception(ENCMQ_ERROR_WRONG_MESSAGE);
    }

    // retrieve serialized message from the envelope
    string str((char *) reply.msg_data().c_str(), reply.msg_size());

    // if encryption is enabled...
    if (m_key != NULL)
    {
        LOG4CPLUS_TRACE(logger, "[encmq::client::receive] Decrypt message.");

        // ...decrypt serialized message
        try
        {
            int num;
            unsigned char * ptr = (unsigned char *) str.c_str();

            if (EVP_DecryptInit_ex(&m_ctx, EVP_aes_128_ofb(), NULL, m_key, NULL) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_DecryptUpdate(&m_ctx, ptr, &num, ptr, str.size()) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_DecryptFinal_ex(&m_ctx, ptr, &num) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);
        }
        catch (...)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::client::receive] " << get_ssl_error());
            throw;
        }

        // ...verify MAC of the message
        string mac((char *) reply.mac_data().c_str(), reply.mac_size());

        if (generate_mac(str) != mac)
        {
            LOG4CPLUS_WARN(logger, "[encmq::client::receive] Unverified MAC.");
            throw exception(ENCMQ_ERROR_WRONG_MAC);
        }
    }

    // unserialize a message from the envelope
    msg->ParseFromString(str);

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

    // envelope of reply
    message::reply reply;

    // receive the envelope
    if (!node::receive(&reply, block))
    {
        LOG4CPLUS_TRACE(logger, "[encmq::client::receive] EXIT = NULL");
        return NULL;
    }

    // retrieve serialized message from the envelope
    string str((char *) reply.msg_data().c_str(), reply.msg_size());

    // if encryption is enabled...
    if (m_key != NULL)
    {
        LOG4CPLUS_TRACE(logger, "[encmq::client::receive] Decrypt message.");

        // ...decrypt serialized message
        try
        {
            int num;
            unsigned char * ptr = (unsigned char *) str.c_str();

            if (EVP_DecryptInit_ex(&m_ctx, EVP_aes_128_ofb(), NULL, m_key, NULL) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_DecryptUpdate(&m_ctx, ptr, &num, ptr, str.size()) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_DecryptFinal_ex(&m_ctx, ptr, &num) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);
        }
        catch (...)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::client::receive] " << get_ssl_error());
            throw;
        }

        // ...verify MAC of the message
        string mac((char *) reply.mac_data().c_str(), reply.mac_size());

        if (generate_mac(str) != mac)
        {
            LOG4CPLUS_WARN(logger, "[encmq::client::receive] Unverified MAC.");
            throw exception(ENCMQ_ERROR_WRONG_MAC);
        }
    }

    // retrieve message type from the envelope
    const Descriptor * desc = DescriptorPool::generated_pool()->FindMessageTypeByName(reply.msg_type());

    if (desc == NULL)
    {
        LOG4CPLUS_WARN(logger,  "[encmq::server::receive] Message type cannot be found by specified name.");
        LOG4CPLUS_TRACE(logger, "[encmq::client::receive] EXIT = NULL");
        return NULL;
    }

    // unserialize a message from the envelope
    Message * msg = (MessageFactory::generated_factory()->GetPrototype(desc))->New();
    msg->ParseFromString(str);

    LOG4CPLUS_TRACE(logger, "[encmq::client::receive] EXIT = " << reply.msg_type());
    return msg;
}

}
