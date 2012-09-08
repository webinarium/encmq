#------------------------------------------------------------------------------
#
#  Copyright (C) 2009-2012 Artem Rodygin
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

project(log4cplus)
cmake_minimum_required(VERSION 2.6)

set(${PROJECT_NAME}_SRC
    src/appender.cxx
    src/appenderattachableimpl.cxx
    src/configurator.cxx
    src/consoleappender.cxx
    src/factory.cxx
    src/fileappender.cxx
    src/filter.cxx
    src/global-init.cxx
    src/hierarchy.cxx
    src/hierarchylocker.cxx
    src/layout.cxx
    src/logger.cxx
    src/loggerimpl.cxx
    src/loggingevent.cxx
    src/loglevel.cxx
    src/loglog.cxx
    src/logloguser.cxx
    src/ndc.cxx
    src/nteventlogappender.cxx
    src/nullappender.cxx
    src/objectregistry.cxx
    src/patternlayout.cxx
    src/pointer.cxx
    src/property.cxx
    src/rootlogger.cxx
    src/sleep.cxx
    src/socket.cxx
    src/socketappender.cxx
    src/socketbuffer.cxx
    src/stringhelper.cxx
    src/syncprims.cxx
    src/syslogappender.cxx
    src/threads.cxx
    src/timehelper.cxx
    src/version.cxx
    src/win32consoleappender.cxx
    src/win32debugappender.cxx)

if (WIN32)
set(${PROJECT_NAME}_SRC ${${PROJECT_NAME}_SRC}
    src/socket-win32.cxx)
else (WIN32)
set(${PROJECT_NAME}_SRC ${${PROJECT_NAME}_SRC}
    src/socket-unix.cxx)
endif (WIN32)

find_package(Threads)

if (UNIX)

    set(HEADER_WARNING "Do not edit. Generated from \"include/log4cplus/config/defines.hxx.in\" by cmake.")

    include(CheckIncludeFile)
    include(CheckFunctionExists)
    include(CheckSymbolExists)

    CHECK_INCLUDE_FILE(errno.h              LOG4CPLUS_HAVE_ERRNO_H)
    CHECK_INCLUDE_FILE(netdb.h              LOG4CPLUS_HAVE_NETDB_H)
    CHECK_INCLUDE_FILE(netinet/in.h         LOG4CPLUS_HAVE_NETINET_IN_H)
    CHECK_INCLUDE_FILE(stdarg.h             LOG4CPLUS_HAVE_STDARG_H)
    CHECK_INCLUDE_FILE(stdio.h              LOG4CPLUS_HAVE_STDIO_H)
    CHECK_INCLUDE_FILE(sys/socket.h         LOG4CPLUS_HAVE_SYS_SOCKET_H)
    CHECK_INCLUDE_FILE(sys/stat.h           LOG4CPLUS_HAVE_SYS_STAT_H)
    CHECK_INCLUDE_FILE(sys/time.h           LOG4CPLUS_HAVE_SYS_TIME_H)
    CHECK_INCLUDE_FILE(sys/timeb.h          LOG4CPLUS_HAVE_SYS_TIMEB_H)
    CHECK_INCLUDE_FILE(sys/types.h          LOG4CPLUS_HAVE_SYS_TYPES_H)
    CHECK_INCLUDE_FILE(syslog.h             LOG4CPLUS_HAVE_SYSLOG_H)
    CHECK_INCLUDE_FILE(time.h               LOG4CPLUS_HAVE_TIME_H)
    CHECK_INCLUDE_FILE(unistd.h             LOG4CPLUS_HAVE_UNISTD_H)
    CHECK_INCLUDE_FILE(wchar.h              LOG4CPLUS_HAVE_WCHAR_H)

    CHECK_FUNCTION_EXISTS(clock_gettime     LOG4CPLUS_HAVE_CLOCK_GETTIME)
    CHECK_FUNCTION_EXISTS(ftime             LOG4CPLUS_HAVE_FTIME)
    CHECK_FUNCTION_EXISTS(getaddrinfo       LOG4CPLUS_HAVE_GETADDRINFO)
    CHECK_FUNCTION_EXISTS(gethostbyname_r   LOG4CPLUS_HAVE_GETHOSTBYNAME_R)
    CHECK_FUNCTION_EXISTS(getpid            LOG4CPLUS_HAVE_GETPID)
    CHECK_FUNCTION_EXISTS(gettimeofday      LOG4CPLUS_HAVE_GETTIMEOFDAY)
    CHECK_FUNCTION_EXISTS(gmtime_r          LOG4CPLUS_HAVE_GMTIME_R)
    CHECK_FUNCTION_EXISTS(htonl             LOG4CPLUS_HAVE_HTONL)
    CHECK_FUNCTION_EXISTS(htons             LOG4CPLUS_HAVE_HTONS)
    CHECK_FUNCTION_EXISTS(localtime_r       LOG4CPLUS_HAVE_LOCALTIME_R)
    CHECK_FUNCTION_EXISTS(lstat             LOG4CPLUS_HAVE_LSTAT)
    CHECK_FUNCTION_EXISTS(ntohl             LOG4CPLUS_HAVE_NTOHL)
    CHECK_FUNCTION_EXISTS(ntohs             LOG4CPLUS_HAVE_NTOHS)
    CHECK_FUNCTION_EXISTS(stat              LOG4CPLUS_HAVE_STAT)

    CHECK_SYMBOL_EXISTS(ENAMETOOLONG    errno.h                     LOG4CPLUS_HAVE_ENAMETOOLONG)
    CHECK_SYMBOL_EXISTS(socklen_t       sys/socket.h sys/types.h    LOG4CPLUS_HAVE_SOCKLEN_T)

    if (LOG4CPLUS_HAVE_SOCKLEN_T)
    set(SOCKLEN_T socklen_t)
    else (LOG4CPLUS_HAVE_SOCKLEN_T)
    set(SOCKLEN_T int)
    endif (LOG4CPLUS_HAVE_SOCKLEN_T)

    if (Threads_FOUND)
    set(LOG4CPLUS_USE_PTHREADS    TRUE)
    else (Threads_FOUND)
    set(LOG4CPLUS_SINGLE_THREADED TRUE)
    endif (Threads_FOUND)

    set(LOG4CPLUS_DECLSPEC_EXPORT "/**/")
    set(LOG4CPLUS_DECLSPEC_IMPORT "/**/")

    configure_file(${PROJECT_SOURCE_DIR}/../include/log4cplus/config/defines.hxx.in
                   ${PROJECT_BINARY_DIR}/../include/log4cplus/config/defines.hxx)

endif (UNIX)

include_directories(${PROJECT_SOURCE_DIR}/../include
                    ${PROJECT_BINARY_DIR}/../include)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
add_definitions(-fPIC)
endif (CMAKE_SIZEOF_VOID_P EQUAL 8)

if (MSVC)
add_definitions(-W0)
add_definitions(-D_SCL_SECURE_NO_WARNINGS)
add_definitions(-DINSIDE_LOG4CPLUS)
else (MSVC)
add_definitions(-w)
endif (MSVC)

if (WIN32)
add_definitions(-DLOG4CPLUS_BUILD_DLL)
endif (WIN32)

add_library(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_SRC})
target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})

if (WIN32)
target_link_libraries(${PROJECT_NAME} ws2_32 advapi32)
endif (WIN32)

message(STATUS "Target '${PROJECT_NAME}' is configured")
message("---------------------------------------------")
