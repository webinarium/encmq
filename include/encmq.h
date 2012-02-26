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

/** @file include/encmq.h
 * Main include file of the Encrypted Messaging Library.
 * @author Artem Rodygin
 */

#ifndef ENCMQ_H
#define ENCMQ_H

// Protocol Buffers
#include <google/protobuf/message.h>

// OpenSSL
#include <openssl/rsa.h>
#include <openssl/evp.h>

/** Modificator for API, exported from this DLL. */
#if defined(_MSC_VER) && defined(_WINDLL)
  #ifdef  encmq_EXPORTS
  #define ENCMQ_EXPORT __declspec(dllexport)
  #else
  #define ENCMQ_EXPORT __declspec(dllimport)
  #endif
#else
  #define ENCMQ_EXPORT
#endif

//-----------------------------------------------------------------------------
//  Constants.
//-----------------------------------------------------------------------------

/** @defgroup loglevel Encrypted Messaging Library logging levels. */
//@{
#define ENCMQ_OFF_LOG_LEVEL         0   /**< No logging.           */
#define ENCMQ_FATAL_LOG_LEVEL       1   /**< Fatal messages.       */
#define ENCMQ_ERROR_LOG_LEVEL       2   /**< Error messages.       */
#define ENCMQ_WARN_LOG_LEVEL        3   /**< Warnings.             */
#define ENCMQ_INFO_LOG_LEVEL        4   /**< Information messages. */
#define ENCMQ_DEBUG_LOG_LEVEL       5   /**< Debug messages.       */
#define ENCMQ_TRACE_LOG_LEVEL       6   /**< Calls trace.          */
//@}

/** @defgroup errcodes Encrypted Messaging Library exception codes. */
//@{
#define ENCMQ_ERROR_UNKNOWN         1   /**< Unknown error.                         */
#define ENCMQ_ERROR_ADDR_IN_USE     2   /**< The given address is already in use.   */
#define ENCMQ_ERROR_ADDR_NOT_FOUND  3   /**< A nonexistent interface was requested. */
#define ENCMQ_ERROR_WRONG_MESSAGE   4   /**< Type of a message is not as expected.  */
#define ENCMQ_ERROR_WRONG_MAC       5   /**< MAC of a message is not as expected.   */
#define ENCMQ_ERROR_SSL_RSA         6   /**< SSL error related to RSA cipher.       */
#define ENCMQ_ERROR_SSL_AES         7   /**< SSL error related to AES cipher.       */
//@}

/** @namespace encmq
 * Encrypted Messaging Library namespace.
 */
namespace encmq
{

using google::protobuf::Message;

//-----------------------------------------------------------------------------
//  Global functions.
//-----------------------------------------------------------------------------

// Initializes the library - must be called once at the client's application start.
ENCMQ_EXPORT void initialize ();

// Sets logging level.
ENCMQ_EXPORT void set_loglevel (int level);

// Generates RSA keys and saves them in specified files.
ENCMQ_EXPORT bool generate_rsa_keys (const char * private_key, const char * public_key);

//-----------------------------------------------------------------------------
//  Encrypted Messaging Library classes.
//-----------------------------------------------------------------------------

/**
 * Encrypted Messaging Library exception.
 */
class exception
{
public:

    ENCMQ_EXPORT exception  (int error);    /**< @private */
    ENCMQ_EXPORT ~exception () throw ();    /**< @private */

    /**
     * @return Exception's error code.
     */
    ENCMQ_EXPORT inline int error () { return m_error; }

protected:

    int m_error;    /**< @private */
};

/**
 * Network node (for internal use only).
 */
class node
{
protected:

    ENCMQ_EXPORT node  (int type, const char * addr, int port);
    ENCMQ_EXPORT ~node () throw ();

    ENCMQ_EXPORT bool      send    (const Message * msg, bool block = true);
    ENCMQ_EXPORT bool      receive (Message       * msg, bool block = true);
    ENCMQ_EXPORT Message * receive (bool block = true);

protected:

    virtual bool before_send   (Message * msg) = 0;
    virtual bool after_receive (Message * msg) = 0;

    virtual bool encrypt (unsigned char * msg_data, int msg_size) = 0;
    virtual bool decrypt (unsigned char * msg_data, int msg_size) = 0;

protected:

    void * m_context;   /**< @private Connection context. */
    void * m_socket;    /**< @private Connection socket.  */
};

/**
 * Server.
 */
class server : public node
{
public:

    ENCMQ_EXPORT server  (const char * addr, int port, const char * keyfile);
    ENCMQ_EXPORT ~server ();

    ENCMQ_EXPORT bool      send    (const Message * msg, bool block = true);
    ENCMQ_EXPORT bool      receive (Message       * msg, bool block = true);
    ENCMQ_EXPORT Message * receive (bool block = true);

protected:

    virtual bool before_send   (Message * msg);
    virtual bool after_receive (Message * msg);

    virtual bool encrypt (unsigned char * msg_data, int msg_size);
    virtual bool decrypt (unsigned char * msg_data, int msg_size);

protected:

    EVP_CIPHER_CTX   m_ctx;     /**< @private AES cipher context.                                       */
    RSA            * m_rsa;     /**< @private RSA keys.                                                 */
    unsigned char  * m_key;     /**< @private Saved client's symmetric key for AES cipher.              */
    bool             use_key;   /**< @private Whether to use saved key when sending response to client. */
};

/**
 * Client.
 */
class client : public node
{
public:

    ENCMQ_EXPORT client  (const char * addr, int port, const char * keyfile = NULL);
    ENCMQ_EXPORT ~client ();

    ENCMQ_EXPORT bool      send    (const Message * msg, bool block = true);
    ENCMQ_EXPORT bool      receive (Message       * msg, bool block = true);
    ENCMQ_EXPORT Message * receive (bool block = true);

protected:

    virtual bool before_send   (Message * msg);
    virtual bool after_receive (Message * msg);

    virtual bool encrypt (unsigned char * msg_data, int msg_size);
    virtual bool decrypt (unsigned char * msg_data, int msg_size);

protected:

    EVP_CIPHER_CTX   m_ctx;     /**< @private AES cipher context.           */
    RSA            * m_rsa;     /**< @private RSA public key from server.   */
    unsigned char  * m_key;     /**< @private Symmetric key for AES cipher. */
};

/**
 * Publisher.
 */
class publisher : public node
{
public:

    ENCMQ_EXPORT publisher (const char * addr, int port);

    ENCMQ_EXPORT bool send (const Message * msg, const char * topic = NULL, bool block = true);

protected:

    virtual bool before_send   (Message * msg);
    virtual bool after_receive (Message * msg);

    virtual bool encrypt (unsigned char * msg_data, int msg_size);
    virtual bool decrypt (unsigned char * msg_data, int msg_size);
};

/**
 * Subscriber.
 */
class subscriber : public node
{
public:

    ENCMQ_EXPORT subscriber (const char * addr, int port);

    ENCMQ_EXPORT bool receive (Message * msg, bool block = true);

    ENCMQ_EXPORT void subscribe   (const char * topic = NULL);
    ENCMQ_EXPORT void unsubscribe (const char * topic = NULL);

protected:

    virtual bool before_send   (Message * msg);
    virtual bool after_receive (Message * msg);

    virtual bool encrypt (unsigned char * msg_data, int msg_size);
    virtual bool decrypt (unsigned char * msg_data, int msg_size);
};

}

#endif  // ENCMQ_H
