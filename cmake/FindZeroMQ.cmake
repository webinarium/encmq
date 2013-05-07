#------------------------------------------------------------------------------
#
#  Copyright (C) 2013 Artem Rodygin
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#------------------------------------------------------------------------------
#
#  This module finds if C API of ZeroMQ is installed and determines where required
#  include files and libraries are. The module sets the following variables:
#
#    ZeroMQ_FOUND         - system has ZeroMQ
#    ZeroMQ_INCLUDE_DIR   - the ZeroMQ include directory
#    ZeroMQ_LIBRARIES     - the libraries needed to use ZeroMQ
#    ZeroMQ_VERSION       - ZeroMQ full version information string
#    ZeroMQ_VERSION_MAJOR - the major version of the ZeroMQ release
#    ZeroMQ_VERSION_MINOR - the minor version of the ZeroMQ release
#    ZeroMQ_VERSION_PATCH - the patch version of the ZeroMQ release
#
#  You can help the module to find ZeroMQ by specifying its root path
#  in environment variable named "ZMQROOTDIR". If this variable is not set
#  then module will search for files in default path as following:
#
#    CMAKE_HOST_WIN32 - "C:\Program Files\ZeroMQ X.Y.Z"
#    CMAKE_HOST_UNIX  - "/usr/local", "/usr"
#
#------------------------------------------------------------------------------

set(ZeroMQ_FOUND TRUE)

# set the search path

if (WIN32)
    file(GLOB ZeroMQ_SEARCH_PATH "C:/Program Files/ZeroMQ*")
else (WIN32)
    file(GLOB ZeroMQ_SEARCH_PATH "/usr/local")
endif (WIN32)

file(TO_CMAKE_PATH "$ENV{ZMQROOTDIR}" ZMQROOTDIR)

# search for headers

find_path(ZeroMQ_INCLUDE_DIR
          NAMES "zmq.h"
                "zmq.hpp"
                "zmq_utils.h"
          PATHS "${ZeroMQ_SEARCH_PATH}"
                "/usr"
          ENV ZMQROOTDIR
          PATH_SUFFIXES "include")

# headers are found

if (ZeroMQ_INCLUDE_DIR)

    # retrieve version information from the header

    file(READ "${ZeroMQ_INCLUDE_DIR}/zmq.h" ZMQ_H_FILE)

    string(REGEX REPLACE ".*#define[ \t]+ZMQ_VERSION_MAJOR[ \t]+([0-9]+).*" "\\1" ZeroMQ_VERSION_MAJOR "${ZMQ_H_FILE}")
    string(REGEX REPLACE ".*#define[ \t]+ZMQ_VERSION_MINOR[ \t]+([0-9]+).*" "\\1" ZeroMQ_VERSION_MINOR "${ZMQ_H_FILE}")
    string(REGEX REPLACE ".*#define[ \t]+ZMQ_VERSION_PATCH[ \t]+([0-9]+).*" "\\1" ZeroMQ_VERSION_PATCH "${ZMQ_H_FILE}")

    set(ZeroMQ_VERSION "${ZeroMQ_VERSION_MAJOR}.${ZeroMQ_VERSION_MINOR}.${ZeroMQ_VERSION_PATCH}")

    # search for library

    if (WIN32)

        file(GLOB ZeroMQ_LIBRARIES
             "${ZMQROOTDIR}/lib/libzmq*.lib"
             "${ZeroMQ_SEARCH_PATH}/lib/libzmq*.lib")

    else (WIN32)

        find_library(ZeroMQ_LIBRARIES
                     NAMES "zmq"
                     PATHS "${ZeroMQ_SEARCH_PATH}"
                           "/usr"
                     ENV ZMQROOTDIR
                     PATH_SUFFIXES "lib")

    endif (WIN32)

endif (ZeroMQ_INCLUDE_DIR)

# headers are not found

if (NOT ZeroMQ_INCLUDE_DIR)
    set(ZeroMQ_FOUND FALSE)
endif (NOT ZeroMQ_INCLUDE_DIR)

# library is not found

if (NOT ZeroMQ_LIBRARIES)
    set(ZeroMQ_FOUND FALSE)
endif (NOT ZeroMQ_LIBRARIES)

# set default error message

if (ZeroMQ_FIND_VERSION)
    set(ZeroMQ_ERROR_MESSAGE "Unable to find ZeroMQ library v${ZeroMQ_FIND_VERSION}")
else (ZeroMQ_FIND_VERSION)
    set(ZeroMQ_ERROR_MESSAGE "Unable to find ZeroMQ library")
endif (ZeroMQ_FIND_VERSION)

# check found version

if (ZeroMQ_FIND_VERSION AND ZeroMQ_FOUND)

    set(ZeroMQ_FOUND_VERSION "${ZeroMQ_VERSION_MAJOR}.${ZeroMQ_VERSION_MINOR}.${ZeroMQ_VERSION_PATCH}")

    if (ZeroMQ_FIND_VERSION_EXACT)
        if (NOT ${ZeroMQ_FOUND_VERSION} VERSION_EQUAL ${ZeroMQ_FIND_VERSION})
            set(ZeroMQ_FOUND FALSE)
        endif (NOT ${ZeroMQ_FOUND_VERSION} VERSION_EQUAL ${ZeroMQ_FIND_VERSION})
    else (ZeroMQ_FIND_VERSION_EXACT)
        if (${ZeroMQ_FOUND_VERSION} VERSION_LESS ${ZeroMQ_FIND_VERSION})
            set(ZeroMQ_FOUND FALSE)
        endif (${ZeroMQ_FOUND_VERSION} VERSION_LESS ${ZeroMQ_FIND_VERSION})
    endif (ZeroMQ_FIND_VERSION_EXACT)

    if (NOT ZeroMQ_FOUND)
        set(ZeroMQ_ERROR_MESSAGE "Unable to find ZeroMQ library v${ZeroMQ_FIND_VERSION} (${ZeroMQ_FOUND_VERSION} was found)")
    endif (NOT ZeroMQ_FOUND)

endif (ZeroMQ_FIND_VERSION AND ZeroMQ_FOUND)

# final status messages

if (ZeroMQ_FOUND)

    if (NOT ZeroMQ_FIND_QUIETLY)
        message(STATUS "Found ZeroMQ ${ZeroMQ_VERSION}")
    endif (NOT ZeroMQ_FIND_QUIETLY)

    mark_as_advanced(ZeroMQ_INCLUDE_DIR
                     ZeroMQ_LIBRARIES)

else (ZeroMQ_FOUND)

    if (ZeroMQ_FIND_REQUIRED)
        message(SEND_ERROR "${ZeroMQ_ERROR_MESSAGE}")
    endif (ZeroMQ_FIND_REQUIRED)

endif (ZeroMQ_FOUND)
