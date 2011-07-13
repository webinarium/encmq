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

/** @file encmq/src/publisher.cc
 * Contains implementation of class "encmq::publisher".
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
//  Implementation of class "encmq::publisher".
//-----------------------------------------------------------------------------

namespace encmq
{

using google::protobuf::Message;

//-----------------------------------------------------------------------------
//  Constructors/destructors.
//-----------------------------------------------------------------------------

/**
 * Binds the publisher to specified network interface.
 *
 * @throw encmq::exception ENCMQ_ERROR_ADDR_IN_USE    - the given interface is already in use.
 * @throw encmq::exception ENCMQ_ERROR_ADDR_NOT_FOUND - a nonexistent interface was requested.
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN        - unknown error.
 */
publisher::publisher (const char * addr,    /**< [in] Interface to bind (e.g. "eth0"). */
                      int          port)    /**< [in] Port to bind.                    */
  : node(ZMQ_PUB, addr, port)
{
    LOG4CPLUS_TRACE(logger, "[encmq::publisher::publisher]");
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
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN - unknown error.
 */
bool publisher::send (const Message * msg,      /**< [in] Message to be sent.                            */
                      const char    * topic,    /**< [in] Optional topic of the message.                 */
                      bool            block)    /**< [in] Whether to block thread until message is sent. */
{
    LOG4CPLUS_TRACE(logger, "[encmq::publisher::send] ENTER");
    LOG4CPLUS_TRACE(logger, "[encmq::publisher::send] topic = " << (topic == NULL ? "NULL" : topic));

    if (topic == NULL || strlen(topic) == 0)
    {
        topic = ".";
    }

    zmq_msg_t message;
    serialize(msg, &message, topic);

    if (zmq_sendmsg(m_socket, &message, (block ? 0 : ZMQ_DONTWAIT)) == ZMQ_ERROR)
    {
        if (errno == EAGAIN)
        {
            zmq_msg_close(&message);
            LOG4CPLUS_TRACE(logger, "[encmq::publisher::send] EXIT = false");
            return false;
        }
        else
        {
            LOG4CPLUS_ERROR(logger, "[encmq::publisher::send] zmq_sendmsg = " << zmq_strerror(errno));
            zmq_msg_close(&message);
            throw exception(ENCMQ_ERROR_UNKNOWN);
        }
    }

    zmq_msg_close(&message);
    LOG4CPLUS_TRACE(logger, "[encmq::publisher::send] EXIT = true");
    return true;
}

}
