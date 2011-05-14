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

/** @file encmq/src/node.cc
 * Contains implementation of class "encmq::node".
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
#include <cstdio>
#include <cstring>

//-----------------------------------------------------------------------------
//  Implementation of class "encmq::node".
//-----------------------------------------------------------------------------

namespace encmq
{

using std::string;
using google::protobuf::Message;

//-----------------------------------------------------------------------------
//  Constructors/destructors.
//-----------------------------------------------------------------------------

/**
 * Connects to the specified address.
 *
 * @throw encmq::exception ENCMQ_ERROR_ADDR_IN_USE    - the given address is already in use.
 * @throw encmq::exception ENCMQ_ERROR_ADDR_NOT_FOUND - a nonexistent interface was requested.
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN        - unknown error.
 */
node::node (int          type,  /**< [in] Type of node: \n
                                          ZMQ_PUB - to publish (can only send), \n
                                          ZMQ_SUB - to subscribe (can only receive), \n
                                          ZMQ_REQ - to request, \n
                                          ZMQ_REP - to reply. */
            const char * addr,  /**< [in] Address: host (e.g. "127.0.0.1"), or interface (e.g. "eth0") */
            int          port)  /**< [in] Port to connect.                                             */
  : m_context(NULL),
    m_socket(NULL)
{
    LOG4CPLUS_TRACE(logger, "[encmq::node::node] ENTER");
    LOG4CPLUS_TRACE(logger, "[encmq::node::node] type = " << type);

    // compose address
    char portline[22];  // enough to fit 64-bit value with ':' and '\0'
    sprintf(portline, ":%d", port);

    string addrline = "tcp://";
    addrline += addr;
    addrline += portline;

    LOG4CPLUS_TRACE(logger, "[encmq::node::node] addrline = " << addrline);

    try
    {
        // initialize ZeroMQ context
        m_context = zmq_init(1);

        if (m_context == NULL)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::node::node] zmq_init = " << zmq_strerror(errno));
            throw exception(ENCMQ_ERROR_UNKNOWN);
        }

        // create ZeroMQ socket
        m_socket = zmq_socket(m_context, type);

        if (m_context == NULL)
        {
            LOG4CPLUS_ERROR(logger, "[encmq::node::node] zmq_socket = " << zmq_strerror(errno));
            throw exception(ENCMQ_ERROR_UNKNOWN);
        }

        // establish a connection
        switch (type)
        {
            case ZMQ_PUB:
            case ZMQ_REP:

                if (zmq_bind(m_socket, addrline.c_str()) != 0)
                {
                    LOG4CPLUS_ERROR(logger, "[encmq::node::node] zmq_bind = " << zmq_strerror(errno));

                    if (errno == EADDRINUSE)
                    {
                        throw exception(ENCMQ_ERROR_ADDR_IN_USE);
                    }
                    else if (errno == EADDRNOTAVAIL)
                    {
                        throw exception(ENCMQ_ERROR_ADDR_NOT_FOUND);
                    }
                    else
                    {
                        throw exception(ENCMQ_ERROR_UNKNOWN);
                    }
                }

                break;

            case ZMQ_SUB:
            case ZMQ_REQ:

                if (zmq_connect(m_socket, addrline.c_str()) != 0)
                {
                    LOG4CPLUS_ERROR(logger, "[encmq::node::node] zmq_connect = " << zmq_strerror(errno));
                    throw exception(ENCMQ_ERROR_UNKNOWN);
                }

                break;

            default:

                throw exception(ENCMQ_ERROR_UNKNOWN);
        }
    }
    catch (...)
    {
        if (m_socket  != NULL) zmq_close(m_socket);
        if (m_context != NULL) zmq_term(m_context);

        throw;
    }

    LOG4CPLUS_TRACE(logger, "[encmq::node::node] EXIT");
}

/**
 * Closes the connection.
 */
node::~node () throw ()
{
    LOG4CPLUS_TRACE(logger, "[encmq::node::~node] ENTER");

    if (zmq_close(m_socket) != 0)
    {
        LOG4CPLUS_ERROR(logger, "[encmq::node::~node] zmq_close = " << zmq_strerror(errno));
    }

    if (zmq_term(m_context) != 0)
    {
        LOG4CPLUS_ERROR(logger, "[encmq::node::~node] zmq_term = " << zmq_strerror(errno));
    }

    LOG4CPLUS_TRACE(logger, "[encmq::node::~node] EXIT");
}

//-----------------------------------------------------------------------------
//  Protected interface.
//-----------------------------------------------------------------------------

/**
 * Sends specified message.
 *
 * @return true  - the message was successfully sent.
 * @return false - the message cannot be sent at the moment (in non-blocking mode only).
 *
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN - unknown error.
 */
bool node::send (const Message * msg,       /**< [in] Message to be sent.                            */
                 bool            block)     /**< [in] Whether to block thread until message is sent. */
{
    LOG4CPLUS_TRACE(logger, "[encmq::node::send] ENTER");
    LOG4CPLUS_TRACE(logger, "[encmq::node::send] block = " << block);

    zmq_msg_t message;
    serialize(msg, &message);

    if (zmq_send(m_socket, &message, (block ? 0 : ZMQ_NOBLOCK)) != 0)
    {
        if (errno == EAGAIN)
        {
            zmq_msg_close(&message);
            LOG4CPLUS_TRACE(logger, "[encmq::node::send] EXIT = false");
            return false;
        }
        else
        {
            LOG4CPLUS_ERROR(logger, "[encmq::node::send] zmq_send = " << zmq_strerror(errno));
            zmq_msg_close(&message);
            throw exception(ENCMQ_ERROR_UNKNOWN);
        }
    }

    zmq_msg_close(&message);
    LOG4CPLUS_TRACE(logger, "[encmq::node::send] EXIT = true");
    return true;
}

/**
 * Receives new message.
 *
 * @return true  - new message was successfully received.
 * @return false - there is no message available at the moment (in non-blocking mode only).
 *
 * @throw encmq::exception ENCMQ_ERROR_UNKNOWN - unknown error.
 */
bool node::receive (Message * msg,      /**< [out] Received message.                                  */
                    bool      block)    /**< [in]  Whether to block thread until message is received. */
{
    LOG4CPLUS_TRACE(logger, "[encmq::node::receive] ENTER");
    LOG4CPLUS_TRACE(logger, "[encmq::node::receive] block = " << block);

    zmq_msg_t message;
    zmq_msg_init(&message);

    if (zmq_recv(m_socket, &message, (block ? 0 : ZMQ_NOBLOCK)) != 0)
    {
        if (errno == EAGAIN)
        {
            zmq_msg_close(&message);
            LOG4CPLUS_TRACE(logger, "[encmq::node::receive] EXIT = false");
            return false;
        }
        else
        {
            LOG4CPLUS_ERROR(logger, "[encmq::node::receive] zmq_recv = " << zmq_strerror(errno));
            zmq_msg_close(&message);
            throw exception(ENCMQ_ERROR_UNKNOWN);
        }
    }

    unserialize(&message, msg);

    zmq_msg_close(&message);
    LOG4CPLUS_TRACE(logger, "[encmq::node::receive] EXIT = true");
    return true;
}

}
