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

/** @file encmq/src/encmq.cc
 * Contains implementation of global Encrypted Messaging Library functions.
 * @author Artem Rodygin
 */

#include <encmq.h>
#include <internal.h>

// ZeroMQ
#include <zmq.h>

// Protocol Buffers
#include <google/protobuf/message.h>

// OpenSSL
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

// C++ Logging Library
#include <log4cplus/logger.h>
#include <log4cplus/configurator.h>

// Standard C/C++ Libraries
#include <cstdio>
#include <cstring>

//-----------------------------------------------------------------------------
//  Implementation of global functions.
//-----------------------------------------------------------------------------

namespace encmq
{

using std::string;
using google::protobuf::Message;

//-----------------------------------------------------------------------------
//  Exported functions.
//-----------------------------------------------------------------------------

/**
 * Initializes the library - must be called once at the client's application start.
 */
void initialize ()
{
    log4cplus::BasicConfigurator::doConfigure();
    logger.setLogLevel(log4cplus::OFF_LOG_LEVEL);
}

/**
 * Sets logging level.
 */
void set_loglevel (int level)   /**< [in] New logging level. */
{
    switch (level)
    {
        case ENCMQ_OFF_LOG_LEVEL:
            logger.setLogLevel(log4cplus::OFF_LOG_LEVEL);
            break;
        case ENCMQ_FATAL_LOG_LEVEL:
            logger.setLogLevel(log4cplus::FATAL_LOG_LEVEL);
            break;
        case ENCMQ_ERROR_LOG_LEVEL:
            logger.setLogLevel(log4cplus::ERROR_LOG_LEVEL);
            break;
        case ENCMQ_WARN_LOG_LEVEL:
            logger.setLogLevel(log4cplus::WARN_LOG_LEVEL);
            break;
        case ENCMQ_INFO_LOG_LEVEL:
            logger.setLogLevel(log4cplus::INFO_LOG_LEVEL);
            break;
        case ENCMQ_DEBUG_LOG_LEVEL:
            logger.setLogLevel(log4cplus::DEBUG_LOG_LEVEL);
            break;
        case ENCMQ_TRACE_LOG_LEVEL:
            logger.setLogLevel(log4cplus::TRACE_LOG_LEVEL);
            break;
        default: ;  // nop
    }
}

/**
 * Generates RSA keys and saves them in specified files.
 *
 * @return true  - RSA keys were successfully generated and saved.
 * @return false - generated RSA keys cannot be saved.
 */
bool generate_rsa_keys (const char * private_key,   /**< [in] Path to PKCS8 file to store RSA private key. */
                        const char * public_key)    /**< [in] Path to X509 file to store RSA public key.   */
{
    LOG4CPLUS_TRACE(logger, "[encmq::generate_rsa_keys] ENTER");

    assert(private_key != NULL);
    assert(public_key  != NULL);

    LOG4CPLUS_TRACE(logger, "[encmq::generate_rsa_keys] private_key = " << private_key);
    LOG4CPLUS_TRACE(logger, "[encmq::generate_rsa_keys] public_key  = " << public_key);

    FILE   * fp  = NULL;
    BIGNUM * bn  = NULL;
    RSA    * rsa = NULL;

    try
    {
        // seed with BigNumber
        bn = BN_new();

        if (BN_set_word(bn, RSA_F4) == 0)
        throw "BigNumber set word error.";

        // generate RSA keys
        rsa = RSA_new();

        if (RSA_generate_key_ex(rsa, 1024, bn, NULL) == 0)
        throw "RSA keys generation error.";

        // save public key
        fp = fopen(public_key, "w");

        if (fp == NULL)
        throw "Cannot create public key file.";

        if (PEM_write_RSAPublicKey(fp, rsa) == 0)
        throw "Cannot write public key file";

        fclose(fp);

        // save private key
        fp = fopen(private_key, "w");

        if (fp == NULL)
        throw "Cannot create private key file.";

        if (PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL) == 0)
        throw "Cannot write private key file";

        fclose(fp);

        // release resources
        RSA_free(rsa);
        BN_clear_free(bn);
    }
    catch (const char * str)
    {
        LOG4CPLUS_ERROR(logger, "[encmq::generate_rsa_keys] " << str);
        LOG4CPLUS_ERROR(logger, "[encmq::generate_rsa_keys] " << get_ssl_error());

        if (fp  != NULL) fclose(fp);
        if (rsa != NULL) RSA_free(rsa);
        if (bn  != NULL) BN_clear_free(bn);

        LOG4CPLUS_TRACE(logger, "[encmq::generate_rsa_keys] EXIT = false");
        return false;
    }

    LOG4CPLUS_TRACE(logger, "[encmq::generate_rsa_keys] EXIT = true");
    return true;
}

//-----------------------------------------------------------------------------
//  Marshaling btw ZeroMQ and Protocol Buffers.
//-----------------------------------------------------------------------------

/**
 * Serializes specified "google::protobuf::Message" into "zmq_msg_t" object and returns it.
 * The function initializes the returned object, and the caller is responsible to free
 * occupied memory by "zmq_msg_close" function.
 */
void serialize (const Message * from,       /**< [in]  Source ProtoBuf message.       */
                zmq_msg_t     * to,         /**< [out] Resulted ZeroMQ message.       */
                const char    * topic)      /**< [in]  Optional topic of the message. */
{
    assert(from != NULL);
    assert(to   != NULL);

    // we need space enough for topic and '\0' terminator
    int topic_len = (topic == NULL || strlen(topic) == 0)
                  ? 0
                  : strlen(topic) + 1;

    // serialize user's message
    string str;
    from->SerializeToString(&str);

    // allocate a message to keep topic and serialized message
    zmq_msg_init_size(to, str.size() + topic_len);
    char * data = (char *) zmq_msg_data(to);

    // copy topic including '\0' terminator
    if (topic_len != 0)
    {
        memcpy(data, topic, topic_len);
    }

    // copy serialized message
    memcpy(data + topic_len, str.c_str(), str.size());
}

/**
 * Unserializes specified "zmq_msg_t" object into "google::protobuf::Message".
 */
void unserialize (const zmq_msg_t * from,       /**< [in]  Source ZeroMQ message.                */
                  Message         * to,         /**< [out] Resulted ProtoBuf message.            */
                  bool              topic)      /**< [in]  Whether the message contains a topic. */
{
    assert(from != NULL);
    assert(to   != NULL);

    char * data = (char *) zmq_msg_data((zmq_msg_t *) from);

    // take an offset to the message part (i.e. skip the topic)
    int offset = topic ? strlen(data) + 1 : 0;

    // prepare buffer with serialized message only (no topic)
    string str(data + offset, zmq_msg_size((zmq_msg_t *) from) - offset);

    // unserialize the message
    to->ParseFromString(str);
}

//-----------------------------------------------------------------------------
//  Other internal functions.
//-----------------------------------------------------------------------------

/**
 * Returns description of last SSL error.
 *
 * @return Message Authentication Code.
 */
string get_ssl_error ()
{
    char buf[120];

    ERR_load_crypto_strings();
    ERR_error_string(ERR_peek_last_error(), buf);
    ERR_free_strings();

    return buf;
}

/**
 * Generates MAC for specified message.
 *
 * @return Message Authentication Code.
 */
string generate_mac (const string & msg)    /**< [in] Source message. */
{
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int  size;

    HMAC(EVP_sha1(), "", 0, (const unsigned char *) msg.c_str(), msg.size(), hmac, &size);

    return string((const char *) hmac, size);
}

//-----------------------------------------------------------------------------
//  Implementation of class "encmq::exception".
//-----------------------------------------------------------------------------

exception::exception (int error) : m_error(error)
{ }

exception::~exception () throw ()
{ }

}
