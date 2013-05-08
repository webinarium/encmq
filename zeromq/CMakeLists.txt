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

project(zmq)
cmake_minimum_required(VERSION 2.6)

find_package(ZeroMQ 2.0)

set(ZMQ_FOUND       ${ZeroMQ_FOUND}       PARENT_SCOPE)
set(ZMQ_VERSION     ${ZeroMQ_VERSION}     PARENT_SCOPE)
set(ZMQ_INCLUDE_DIR ${ZeroMQ_INCLUDE_DIR} PARENT_SCOPE)
set(ZMQ_LIBRARIES   ${ZeroMQ_LIBRARIES}   PARENT_SCOPE)

if (NOT ZeroMQ_FOUND)

    if (MSVC)

        configure_file(hdr/platform.hpp.msvc ${PROJECT_BINARY_DIR}/../include/zeromq/platform.hpp COPYONLY)

        add_definitions(-W0)

        add_definitions(-DDLL_EXPORT)
        add_definitions(-DFD_SETSIZE=1024)

    else (MSVC)

        set(HEADER_WARNING "Do not edit. Generated from \"zeromq/hdr/platform.hpp.cmake\" by cmake.")

        include(CheckIncludeFile)
        include(CheckFunctionExists)
        include(CheckLibraryExists)
        include(CheckSymbolExists)
        include(CheckCXXSourceCompiles)

        CHECK_INCLUDE_FILE(alloca.h         HAVE_ALLOCA_H)
        CHECK_INCLUDE_FILE(arpa/inet.h      HAVE_ARPA_INET_H)
        CHECK_INCLUDE_FILE(dlfcn.h          HAVE_DLFCN_H)
        CHECK_INCLUDE_FILE(errno.h          HAVE_ERRNO_H)
        CHECK_INCLUDE_FILE(ifaddrs.h        HAVE_IFADDRS_H)
        CHECK_INCLUDE_FILE(inttypes.h       HAVE_INTTYPES_H)
        CHECK_INCLUDE_FILE(limits.h         HAVE_LIMITS_H)
        CHECK_INCLUDE_FILE(memory.h         HAVE_MEMORY_H)
        CHECK_INCLUDE_FILE(netinet/in.h     HAVE_NETINET_IN_H)
        CHECK_INCLUDE_FILE(netinet/tcp.h    HAVE_NETINET_TCP_H)
        CHECK_INCLUDE_FILE(stdbool.h        HAVE_STDBOOL_H)
        CHECK_INCLUDE_FILE(stddef.h         HAVE_STDDEF_H)
        CHECK_INCLUDE_FILE(stdint.h         HAVE_STDINT_H)
        CHECK_INCLUDE_FILE(stdlib.h         HAVE_STDLIB_H)
        CHECK_INCLUDE_FILE(string.h         HAVE_STRING_H)
        CHECK_INCLUDE_FILE(strings.h        HAVE_STRINGS_H)
        CHECK_INCLUDE_FILE(sys/eventfd.h    HAVE_SYS_EVENTFD_H)
        CHECK_INCLUDE_FILE(sys/socket.h     HAVE_SYS_SOCKET_H)
        CHECK_INCLUDE_FILE(sys/stat.h       HAVE_SYS_STAT_H)
        CHECK_INCLUDE_FILE(sys/time.h       HAVE_SYS_TIME_H)
        CHECK_INCLUDE_FILE(sys/types.h      HAVE_SYS_TYPES_H)
        CHECK_INCLUDE_FILE(time.h           HAVE_TIME_H)
        CHECK_INCLUDE_FILE(unistd.h         HAVE_UNISTD_H)
        CHECK_INCLUDE_FILE(windows.h        HAVE_WINDOWS_H)

        if (HAVE_STDDEF_H AND HAVE_STDINT_H)
        set(STDC_HEADERS TRUE)
        endif (HAVE_STDDEF_H AND HAVE_STDINT_H)

        if (HAVE_SYS_TIME_H AND HAVE_TIME_H)
        set(TIME_WITH_SYS_TIME TRUE)
        endif (HAVE_SYS_TIME_H AND HAVE_TIME_H)

        if (HAVE_SYS_EVENTFD_H)
        set(ZMQ_HAVE_EVENTFD TRUE)
        endif (HAVE_SYS_EVENTFD_H)

        CHECK_FUNCTION_EXISTS(clock_gettime HAVE_CLOCK_GETTIME)
        CHECK_FUNCTION_EXISTS(freeifaddrs   HAVE_FREEIFADDRS)
        CHECK_FUNCTION_EXISTS(gethrtime     HAVE_GETHRTIME)
        CHECK_FUNCTION_EXISTS(getifaddrs    HAVE_GETIFADDRS)
        CHECK_FUNCTION_EXISTS(gettimeofday  HAVE_GETTIMEOFDAY)
        CHECK_FUNCTION_EXISTS(memset        HAVE_MEMSET)
        CHECK_FUNCTION_EXISTS(perror        HAVE_PERROR)
        CHECK_FUNCTION_EXISTS(socket        HAVE_SOCKET)

        CHECK_LIBRARY_EXISTS("pthread" "pthread_create" "" HAVE_LIBPTHREAD)
        CHECK_LIBRARY_EXISTS("stdc++"  "malloc"         "" HAVE_LIBSTDC__)
        CHECK_LIBRARY_EXISTS("m"       "matherr"        "" HAVE_LIBM)

        CHECK_SYMBOL_EXISTS("SOCK_CLOEXEC" sys/socket.h HAVE_SOCK_CLOEXEC)
        CHECK_SYMBOL_EXISTS("_Bool" stdbool.h HAVE__BOOL)

        add_definitions(-D_REENTRANT)
        add_definitions(-D_PTHREAD_SAFE)

        string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} HOST_OS)

        if (HOST_OS MATCHES linux)

            set(ZMQ_HAVE_LINUX TRUE)

            add_definitions(-D_GNU_SOURCE)

            CHECK_LIBRARY_EXISTS("rt"   "sem_init"      "" HAVE_LIBRT)
            CHECK_LIBRARY_EXISTS("uuid" "uuid_generate" "" HAVE_LIBUUID)

            if (NOT HAVE_LIBUUID)
            message(FATAL_ERROR "cannot link with -luuid, install uuid-dev.")
            endif (NOT HAVE_LIBUUID)

        elseif (HOST_OS MATCHES android)

            set(ZMQ_HAVE_ANDROID TRUE)

        elseif (HOST_OS MATCHES solaris)

            set(ZMQ_HAVE_SOLARIS  TRUE)
            set(ZMQ_FORCE_MUTEXES TRUE)

            add_definitions(-D_POSIX_C_SOURCE=200112L)
            add_definitions(-D_PTHREADS)

            CHECK_LIBRARY_EXISTS("socket" "socket"        "" HAVE_LIBSOCKET)
            CHECK_LIBRARY_EXISTS("nsl"    "gethostbyname" "" HAVE_LIBNSL)
            CHECK_LIBRARY_EXISTS("rt"     "sem_init"      "" HAVE_LIBRT)
            CHECK_LIBRARY_EXISTS("uuid"   "uuid_generate" "" HAVE_LIBUUID)

            if (NOT HAVE_LIBUUID)
            message(FATAL_ERROR "cannot link with -luuid, install uuid-dev.")
            endif (NOT HAVE_LIBUUID)

        elseif (HOST_OS MATCHES freebsd)

            set(ZMQ_HAVE_FREEBSD TRUE)

            add_definitions(-D__BSD_VISIBLE)

        elseif (HOST_OS MATCHES darwin)

            set(ZMQ_HAVE_OSX TRUE)

            add_definitions(-D_DARWIN_C_SOURCE)
            add_definitions(-Wno-uninitialized)

        elseif (HOST_OS MATCHES netbsd)

            set(ZMQ_HAVE_NETBSD   TRUE)
            set(ZMQ_FORCE_MUTEXES TRUE)

            add_definitions(-D_NETBSD_SOURCE)

        elseif (HOST_OS MATCHES openbsd)

            set(ZMQ_HAVE_OPENBSD TRUE)

            add_definitions(-D_BSD_SOURCE)

        elseif (HOST_OS MATCHES nto-qnx)

            set(ZMQ_HAVE_QNXNTO TRUE)

            CHECK_LIBRARY_EXISTS("socket" "socket"     "" HAVE_LIBSOCKET)
            CHECK_LIBRARY_EXISTS("crypto" "RAND_bytes" "" HAVE_LIBCRYPTO)

        elseif (HOST_OS MATCHES aix)

            set(ZMQ_HAVE_AIX TRUE)

            CHECK_LIBRARY_EXISTS("crypto" "RAND_bytes" "" HAVE_LIBCRYPTO)

        elseif (HOST_OS MATCHES hpux)

            set(ZMQ_HAVE_HPUX TRUE)

            add_definitions(-D_POSIX_C_SOURCE=200112L)

            CHECK_LIBRARY_EXISTS("rt"     "sem_init"    "" HAVE_LIBRT)
            CHECK_LIBRARY_EXISTS("dcekt"  "uuid_create" "" HAVE_LIBDCEKT)
            CHECK_LIBRARY_EXISTS("crypto" "RAND_bytes"  "" HAVE_LIBCRYPTO)

        elseif (HOST_OS MATCHES mingw32)

            set(ZMQ_HAVE_WINDOWS TRUE)
            set(ZMQ_HAVE_MINGW32 TRUE)

            add_definitions(-std=c99)

            CHECK_LIBRARY_EXISTS("ws2_32"   "main" "" HAVE_LIBWS2_32)
            CHECK_LIBRARY_EXISTS("rpcrt4"   "main" "" HAVE_LIBRPCRT4)
            CHECK_LIBRARY_EXISTS("iphlpapi" "main" "" HAVE_LIBIPHLPAPI)

            if (NOT HAVE_LIBWS2_32)
            message(FATAL_ERROR "cannot link with ws2_32.dll.")
            endif (NOT HAVE_LIBWS2_32)

            if (NOT HAVE_LIBRPCRT4)
            message(FATAL_ERROR "cannot link with rpcrt4.dll.")
            endif (NOT HAVE_LIBRPCRT4)

            if (NOT HAVE_LIBIPHLPAPI)
            message(FATAL_ERROR "cannot link with iphlpapi.dll.")
            endif (NOT HAVE_LIBIPHLPAPI)

        elseif (HOST_OS MATCHES cygwin)

            set(ZMQ_HAVE_CYGWIN TRUE)

            add_definitions(-D_GNU_SOURCE)

            CHECK_LIBRARY_EXISTS("uuid" "uuid_generate" "" HAVE_LIBUUID)

            if (NOT HAVE_LIBUUID)
            message(FATAL_ERROR "cannot link with -luuid, install the e2fsprogs package.")
            endif (NOT HAVE_LIBUUID)

        else (HOST_OS MATCHES linux)

            message(FATAL_ERROR "Not supported os: ${CMAKE_HOST_SYSTEM_NAME}")

        endif (HOST_OS MATCHES linux)

        CHECK_INCLUDE_FILE(sys/eventfd.h    ZMQ_HAVE_EVENTFD)
        CHECK_INCLUDE_FILE(ifaddrs.h        ZMQ_HAVE_IFADDRS)

        if (WIN32)
        set(LT_OBJDIR "_libs/")
        else (WIN32)
        set(LT_OBJDIR ".libs/")
        endif (WIN32)

        set(RETSIGTYPE_SRC "
            #include <sys/types.h>
            #include <signal.h>
            int main ()
            {
                return *(signal (0, 0)) (0) == 1;
                return 0;
            }")

        CHECK_CXX_SOURCE_COMPILES("${RETSIGTYPE_SRC}" RETSIGTYPE_RES)

        if (RETSIGTYPE_RES)
        set(RETSIGTYPE "int")
        else (RETSIGTYPE_RES)
        set(RETSIGTYPE "void")
        endif (RETSIGTYPE_RES)

        configure_file(hdr/platform.hpp.cmake ${PROJECT_BINARY_DIR}/../include/zeromq/platform.hpp)

    endif (MSVC)

    aux_source_directory(src ${PROJECT_NAME}_SRC)

    include_directories(${PROJECT_SOURCE_DIR}/../include
                        ${PROJECT_BINARY_DIR}/../include/zeromq
                        ${PROJECT_SOURCE_DIR})

    add_library(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_SRC})

    if (WIN32)
    target_link_libraries(${PROJECT_NAME} ws2_32 rpcrt4)
    endif (WIN32)

    if (UNIX)
    target_link_libraries(${PROJECT_NAME} pthread)
    endif (UNIX)

    if (HAVE_LIBUUID)
    target_link_libraries(${PROJECT_NAME} uuid)
    endif (HAVE_LIBUUID)

endif (NOT ZeroMQ_FOUND)

message(STATUS "Target '${PROJECT_NAME}' is configured")
message("---------------------------------------------")
