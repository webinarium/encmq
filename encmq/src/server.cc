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

/** @file encmq/src/server.cc
 * Contains implementation of class "encmq::server".
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
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
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
using google::protobuf::MessageFactory;
using google::protobuf::Descriptor;
using google::protobuf::DescriptorPool;

//-----------------------------------------------------------------------------
//  Constructors/destructors.
//-----------------------------------------------------------------------------

/**
 * Binds the server to specified network interface.
 *
 * @throw encmq::exception ENCMQ_ERROR_ADDR_IN_USE    - the given interface is already in use.
 * @throw encmq::exception ENCMQ_ERROR_ADDR_NOT_FOUND - a nonexistent interface was requested.
 * @throw encmq::exception ENCMQ_ERROR_SSL_RSA        - error on RSA key retrieval/generation.
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
    LOG4CPLUS_TRACE(logger, "[encmq::server::server] ENTER");
    LOG4CPLUS_TRACE(logger, "[encmq::server::server] keyfile = " << (keyfile == NULL ? "NULL" : keyfile));

    EVP_CIPHER_CTX_init(&m_ctx);

    // retrieve RSA private key
    try
    {
        if (keyfile == NULL)
        {
            LOG4CPLUS_TRACE(logger, "[encmq::server::server] Generate RSA private key.");

            BIGNUM * bignum = BN_new();

            if (BN_set_word(bignum, RSA_F4) == 0)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            if (RSA_generate_key_ex(m_rsa, ENCMQ_RSA_LENGTH, bignum, NULL) == 0)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            BN_clear_free(bignum);
        }
        else
        {
            LOG4CPLUS_TRACE(logger, "[encmq::server::server] Load RSA private key from file.");

            FILE * fp = fopen(keyfile, "r");

            if (fp == NULL)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            if (PEM_read_RSAPrivateKey(fp, &m_rsa, NULL, NULL) == 0)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            if (RSA_check_key(m_rsa) == 0)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            fclose(fp);
        }
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

    assert(msg != NULL);

    // envelope of reply
    message::reply reply;
    reply.set_mac_size(0);

    // serialize message for the envelope
    string str;
    msg->SerializeToString(&str);

    // if encryption was requested by client...
    if (use_key)
    {
        LOG4CPLUS_TRACE(logger, "[encmq::server::send] Encrypt message.");

        use_key = false;

        // ...add MAC to the message
        string mac = generate_mac(str);

        reply.set_mac_size(mac.size());
        reply.set_mac_data((void *) mac.c_str(), mac.size());

        // ...encrypt serialized message
        int num;
        unsigned char * ptr = (unsigned char *) str.c_str();

        try
        {
            if (EVP_EncryptInit_ex(&m_ctx, EVP_aes_128_ofb(), NULL, m_key, NULL) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_EncryptUpdate(&m_ctx, ptr, &num, ptr, str.size()) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_EncryptFinal_ex(&m_ctx, ptr, &num) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);
        }
        catch (...)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::send] " << get_ssl_error());
            throw;
        }
    }

    // put serialized message to the envelope
    reply.set_msg_type(msg->GetDescriptor()->full_name());
    reply.set_msg_size(str.size());
    reply.set_msg_data((void *) str.c_str(), str.size());

    // send the envelope
    return node::send(&reply, block);
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

    assert(msg   != NULL);
    assert(m_rsa != NULL);

    again:

    // envelope of request
    message::request request;

    // receive the envelope
    if (!node::receive(&request, block))
    {
        LOG4CPLUS_TRACE(logger, "[encmq::server::receive] EXIT = false");
        return false;
    }

    // whether the received message is a request for RSA public key
    if (request.msg_type() == message::rsa_hello::descriptor()->full_name())
    {
        LOG4CPLUS_TRACE(logger, "[encmq::server::receive] Sending RSA public key.");

        message::rsa_key rsa_key;

        try
        {
            BIO * mem = BIO_new(BIO_s_mem());

            if (PEM_write_bio_RSAPublicKey(mem, m_rsa) == 0)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            BUF_MEM * bptr;
            BIO_get_mem_ptr(mem, &bptr);

            rsa_key.set_key_size(bptr->length);
            rsa_key.set_key_data(bptr->data, bptr->length);

            BIO_free(mem);
        }
        catch (...)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::receive] " << get_ssl_error());
            throw;
        }

        node::send(&rsa_key, false);
        goto again;
    }

    // check message type descriptor
    if (request.msg_type() != msg->GetDescriptor()->full_name())
    {
        LOG4CPLUS_WARN(logger, "[encmq::server::receive] Received message type is not as expected.");
        throw exception(ENCMQ_ERROR_WRONG_MESSAGE);
    }

    // retrieve serialized message from the envelope
    string str((char *) request.msg_data().c_str(), request.msg_size());

    // decrypt serialized message
    use_key = (request.key_size() != 0);

    if (use_key)
    {
        LOG4CPLUS_TRACE(logger, "[encmq::server::receive] Decrypt message.");

        try
        {
            int num;
            unsigned char * ptr = (unsigned char *) str.c_str();

            if (RSA_private_decrypt(request.key_size(), (unsigned char *) request.key_data().c_str(), m_key, m_rsa, ENCMQ_RSA_PADDING) == -1)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            if (EVP_DecryptInit_ex(&m_ctx, EVP_aes_128_ofb(), NULL, m_key, NULL) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_DecryptUpdate(&m_ctx, ptr, &num, ptr, str.size()) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_DecryptFinal_ex(&m_ctx, ptr, &num) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);
        }
        catch (...)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::receive] " << get_ssl_error());
            throw;
        }

        // verify MAC of the message
        string mac((char *) request.mac_data().c_str(), request.mac_size());

        if (generate_mac(str) != mac)
        {
            LOG4CPLUS_WARN(logger, "[encmq::server::receive] Unverified MAC.");
            throw exception(ENCMQ_ERROR_WRONG_MAC);
        }
    }

    // unserialize a message from the envelope
    msg->ParseFromString(str);

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

    assert(m_rsa != NULL);

    again:

    // envelope of request
    message::request request;

    // receive the envelope
    if (!node::receive(&request, block))
    {
        LOG4CPLUS_TRACE(logger, "[encmq::server::receive] EXIT = NULL");
        return NULL;
    }

    // whether the received message is a request for RSA public key
    if (request.msg_type() == message::rsa_hello::descriptor()->full_name())
    {
        LOG4CPLUS_TRACE(logger, "[encmq::server::receive] Sending RSA public key.");

        message::rsa_key rsa_key;

        try
        {
            BIO * mem = BIO_new(BIO_s_mem());

            if (PEM_write_bio_RSAPublicKey(mem, m_rsa) == 0)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            BUF_MEM * bptr;
            BIO_get_mem_ptr(mem, &bptr);

            rsa_key.set_key_size(bptr->length);
            rsa_key.set_key_data(bptr->data, bptr->length);

            BIO_free(mem);
        }
        catch (...)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::receive] " << get_ssl_error());
            throw;
        }

        node::send(&rsa_key, false);
        goto again;
    }

    // retrieve serialized message from the envelope
    string str((char *) request.msg_data().c_str(), request.msg_size());

    // decrypt serialized message
    use_key = (request.key_size() != 0);

    if (use_key)
    {
        LOG4CPLUS_TRACE(logger, "[encmq::server::receive] Decrypt message.");

        try
        {
            int num;
            unsigned char * ptr = (unsigned char *) str.c_str();

            if (RSA_private_decrypt(request.key_size(), (unsigned char *) request.key_data().c_str(), m_key, m_rsa, ENCMQ_RSA_PADDING) == -1)
            throw exception(ENCMQ_ERROR_SSL_RSA);

            if (EVP_DecryptInit_ex(&m_ctx, EVP_aes_128_ofb(), NULL, m_key, NULL) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_DecryptUpdate(&m_ctx, ptr, &num, ptr, str.size()) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);

            if (EVP_DecryptFinal_ex(&m_ctx, ptr, &num) == 0)
            throw exception(ENCMQ_ERROR_SSL_AES);
        }
        catch (...)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::server::receive] " << get_ssl_error());
            throw;
        }

        // verify MAC of the message
        string mac((char *) request.mac_data().c_str(), request.mac_size());

        if (generate_mac(str) != mac)
        {
            LOG4CPLUS_WARN(logger, "[encmq::server::receive] Unverified MAC.");
            throw exception(ENCMQ_ERROR_WRONG_MAC);
        }
    }

    // retrieve message type from the envelope
    const Descriptor * desc = DescriptorPool::generated_pool()->FindMessageTypeByName(request.msg_type());

    if (desc == NULL)
    {
        LOG4CPLUS_WARN(logger,  "[encmq::server::receive] Message type cannot be found by specified name.");
        LOG4CPLUS_TRACE(logger, "[encmq::server::receive] EXIT = NULL");
        return NULL;
    }

    // unserialize a message from the envelope
    Message * msg = (MessageFactory::generated_factory()->GetPrototype(desc))->New();
    msg->ParseFromString(str);

    LOG4CPLUS_TRACE(logger, "[encmq::server::receive] EXIT = " << request.msg_type());
    return msg;
}

}
