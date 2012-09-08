#------------------------------------------------------------------------------
#
#  Copyright (C) 2011-2012 Artem Rodygin
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

project(keygen)
cmake_minimum_required(VERSION 2.6)

find_package(OpenSSL QUIET REQUIRED)

aux_source_directory(src ${PROJECT_NAME}_SRC)

if (WIN32)
list(APPEND ${PROJECT_NAME}_SRC ${OPENSSL_INCLUDE_DIR}/openssl/applink.c)
endif (WIN32)

include_directories(${OPENSSL_INCLUDE_DIR}
                    ${PROJECT_SOURCE_DIR}/../include
                    ${PROJECT_BINARY_DIR}/../include)

link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SRC} ${${PROJECT_NAME}_HDR})

add_dependencies(${PROJECT_NAME} encmq)

target_link_libraries(${PROJECT_NAME} encmq)

if (MSVC)
add_definitions(-W3 -D_CRT_SECURE_NO_WARNINGS)
else (MSVC)
add_definitions(-Wall -Wextra -Wno-sign-compare -ansi)
endif (MSVC)

message(STATUS "Target '${PROJECT_NAME}' is configured")
message("---------------------------------------------")
