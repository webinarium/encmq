#------------------------------------------------------------------------------
#
#  Copyright (C) 2010-2012 Artem Rodygin
#
#  This file is part of EncMQ.
#
#  EncMQ is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  EncMQ is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with EncMQ.  If not, see <http://www.gnu.org/licenses/>.
#
#------------------------------------------------------------------------------

project(encmq)
cmake_minimum_required(VERSION 2.6)

find_package(OpenSSL QUIET REQUIRED)

if (NOT ZMQ_FOUND)
set(ZMQ_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/../vendor/zeromq/include)
set(ZMQ_LIBRARIES   zmq)
endif (NOT ZMQ_FOUND)

include_directories(${OPENSSL_INCLUDE_DIR}
                    ${ZMQ_INCLUDE_DIR}
                    ${PROJECT_SOURCE_DIR}/../vendor/log4cplus/include
                    ${PROJECT_SOURCE_DIR}/../vendor/protobuf/include
                    ${PROJECT_SOURCE_DIR}/../encmq/include
                    ${PROJECT_BINARY_DIR}/../include
                    hdr)

aux_source_directory(src ${PROJECT_NAME}_SRC)
file(GLOB ${PROJECT_NAME}_HDR "hdr/*.h")

if (WIN32)
list(APPEND ${PROJECT_NAME}_SRC ${OPENSSL_INCLUDE_DIR}/openssl/applink.c)
endif (WIN32)

add_library(${PROJECT_NAME} STATIC
            ${${PROJECT_NAME}_SRC}
            ${${PROJECT_NAME}_HDR}
            ${PROJECT_SOURCE_DIR}/../encmq/include/encmq.h)

add_dependencies(${PROJECT_NAME}
                 log4cplus
                 protobuf
                 zmq)

target_link_libraries(${PROJECT_NAME}
                      ${OPENSSL_LIBRARIES}
                      ${ZMQ_LIBRARIES}
                      log4cplus
                      protobuf)

if (WIN32)
target_link_libraries(${PROJECT_NAME} wsock32 advapi32 gdi32 user32)
endif (WIN32)

if (MSVC)
add_definitions(-W3 -D_CRT_SECURE_NO_WARNINGS)
else (MSVC)
add_definitions(-Wall -Wextra -Wno-sign-compare -ansi)
endif (MSVC)

message(STATUS "Target '${PROJECT_NAME}' is configured")
message("---------------------------------------------")
