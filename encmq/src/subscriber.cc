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

/** @file encmq/src/subscriber.cc
 * Contains implementation of class "encmq::subscriber".
 * @author Artem Rodygin
 */

#include <encmq.h>
#include <internal.h>

// ZeroMQ
#include <zmq.h>

// Protocol Buffers
#include <google/protobuf/message.h>

// C++ Logging Library
#include <log4cplus/logger.h>

// Standard C/C++ Libraries
#include <cstring>

//-----------------------------------------------------------------------------
//  Implementation of class "encmq::subscriber".
//-----------------------------------------------------------------------------

namespace encmq
{

using google::protobuf::Message;

//-----------------------------------------------------------------------------
//  Constructors/destructors.
//-----------------------------------------------------------------------------

/**
 * Connects to the specified publisher.
 *
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN - unknown error.
 */
subscriber::subscriber (const char * addr,      /**< [in] Address of the publisher (e.g. "127.0.0.1"). */
                        int          port)      /**< [in] Port of the publisher.                       */
  : node(ZMQ_SUB, addr, port)
{
    LOG4CPLUS_TRACE(logger, "[encmq::subscriber::subscriber]");
}

//-----------------------------------------------------------------------------
//  Public interface.
//-----------------------------------------------------------------------------

/**
 * Receives new message.
 *
 * @return true  - new message was successfully received.
 * @return false - there is no message available at the moment (in non-blocking mode only).
 *
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN - unknown error.
 */
bool subscriber::receive (Message * msg,        /**< [out] Received message.                                  */
                          bool      block)      /**< [in]  Whether to block thread until message is received. */
{
    LOG4CPLUS_TRACE(logger, "[encmq::subscriber::receive] ENTER");

    zmq_msg_t message;
    zmq_msg_init(&message);

    if (zmq_recvmsg(m_socket, &message, (block ? 0 : ZMQ_DONTWAIT)) == ZMQ_ERROR)
    {
        if (errno == EAGAIN)
        {
            zmq_msg_close(&message);
            LOG4CPLUS_TRACE(logger, "[encmq::subscriber::receive] EXIT = false");
            return false;
        }
        else
        {
            LOG4CPLUS_ERROR(logger, "[encmq::subscriber::receive] zmq_recvmsg = " << zmq_strerror(errno));
            zmq_msg_close(&message);
            throw exception(ENCMQ_ERROR_UNKNOWN);
        }
    }

    unserialize(&message, msg, true);

    zmq_msg_close(&message);
    LOG4CPLUS_TRACE(logger, "[encmq::subscriber::receive] EXIT = true");
    return true;
}

/**
 * Subscribes to specified topic(s).
 *
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN - unknown error.
 */
void subscriber::subscribe (const char * topic)     /**< [in] Topic(s) to subscribe (empty for all topics). */
{
    LOG4CPLUS_TRACE(logger, "[encmq::subscriber::subscribe] ENTER");
    LOG4CPLUS_TRACE(logger, "[encmq::subscriber::subscribe] topic = " << (topic == NULL ? "NULL" : topic));

    int topic_len = (topic == NULL ? 0 : strlen(topic));
    if (topic_len > 0 && topic[topic_len - 1] != '.') topic_len++;

    if (zmq_setsockopt(m_socket, ZMQ_SUBSCRIBE, topic, topic_len) == ZMQ_ERROR)
    {
        LOG4CPLUS_ERROR(logger, "[encmq::subscriber::subscribe] zmq_setsockopt = " << zmq_strerror(errno));
        throw exception(ENCMQ_ERROR_UNKNOWN);
    }

    LOG4CPLUS_TRACE(logger, "[encmq::subscriber::subscribe] EXIT");
}

/**
 * Unsubscribes from specified topic(s).
 *
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN - unknown error.
 */
void subscriber::unsubscribe (const char * topic)   /**< [in] Topic(s) to unsubscribe (empty for all topics). */
{
    LOG4CPLUS_TRACE(logger, "[encmq::subscriber::unsubscribe] ENTER");
    LOG4CPLUS_TRACE(logger, "[encmq::subscriber::unsubscribe] topic = " << (topic == NULL ? "NULL" : topic));

    int topic_len = (topic == NULL ? 0 : strlen(topic));
    if (topic_len > 0 && topic[topic_len - 1] != '.') topic_len++;

    if (zmq_setsockopt(m_socket, ZMQ_UNSUBSCRIBE, topic, topic_len) == ZMQ_ERROR)
    {
        LOG4CPLUS_ERROR(logger, "[encmq::subscriber::unsubscribe] zmq_setsockopt = " << zmq_strerror(errno));
        throw exception(ENCMQ_ERROR_UNKNOWN);
    }

    LOG4CPLUS_TRACE(logger, "[encmq::subscriber::unsubscribe] EXIT");
}

//-----------------------------------------------------------------------------
//  Protected interface.
//-----------------------------------------------------------------------------

/**
 * Stub implementation.
 *
 * @return Always true.
 */
bool subscriber::before_send (Message *)
{
    return true;
}

/**
 * Stub implementation.
 *
 * @return Always true.
 */
bool subscriber::after_receive (Message *)
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
bool subscriber::encrypt (unsigned char *, int)
{
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
bool subscriber::decrypt (unsigned char *, int)
{
    return true;
}

}
