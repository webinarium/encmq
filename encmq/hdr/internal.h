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

/** @file encmq/hdr/internal.h
 * Internal include file with global Encrypted Messaging Library functions.
 * @author Artem Rodygin
 */

#ifndef ENCMQ_INTERNAL_H
#define ENCMQ_INTERNAL_H

// Protocol Buffers
#include <google/protobuf/message.h>

// ZeroMQ
#include <zmq.h>

// C++ Logging Library
#include <log4cplus/logger.h>
#include <log4cplus/configurator.h>

// Standard C/C++ Libraries
#include <cstdio>
#include <cstring>

//-----------------------------------------------------------------------------
//  For backward compatibility btw ZeroMQ 2 and ZeroMQ 3
//-----------------------------------------------------------------------------

#define ZMQ_ERROR       -1

#if ZMQ_VERSION_MAJOR == 2
#define ZMQ_DONTWAIT    ZMQ_NOBLOCK
#define zmq_recvmsg     zmq_recv
#define zmq_sendmsg     zmq_send
#endif

//-----------------------------------------------------------------------------
//  Constants.
//-----------------------------------------------------------------------------

/** Name of library's logging port. */
#define ENCMQ_LOGGER_PORT  "encmq"

/** RSA parameters. */
#define ENCMQ_RSA_LENGTH   1024                     /**< RSA key bit length. */
#define ENCMQ_RSA_PADDING  RSA_PKCS1_OAEP_PADDING   /**< RSA padding mode.   */

/** @namespace encmq
 * Encrypted Messaging Library namespace.
 */
namespace encmq
{

using std::string;
using google::protobuf::Message;

//-----------------------------------------------------------------------------
//  Static variables.
//-----------------------------------------------------------------------------

/** @private Library's logger. */
static log4cplus::Logger logger = log4cplus::Logger::getInstance(ENCMQ_LOGGER_PORT);

//-----------------------------------------------------------------------------
//  Static functions.
//-----------------------------------------------------------------------------

/** @defgroup serialization Serialization between ZeroMQ and Protocol Buffers. */
//@{
void serialize   (const Message   * from, zmq_msg_t * to, const char * topic = NULL);
void unserialize (const zmq_msg_t * from, Message   * to, bool topic = false);
//@}

/** Other internal functions. */
string get_ssl_error ();
string generate_mac  (const string & msg);

}

#endif  // ENCMQ_INTERNAL_H
