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

project(protobuf)
cmake_minimum_required(VERSION 2.6)

if (MSVC)

    configure_file(hdr/config.h.msvc ${PROJECT_BINARY_DIR}/../include/protobuf/config.h COPYONLY)

else (MSVC)

    set(HEADER_WARNING "Do not edit. Generated from \"protobuf/hdr/config.h.cmake\" by cmake.")

    include(CheckIncludeFile)
    include(CheckFunctionExists)
    include(CheckSymbolExists)
    include(CheckCXXSourceCompiles)

    set(HASH_LOCATIONS  ext/ )
    set(HASH_NAMESPACES __gnu_cxx std stdext)

    list(LENGTH HASH_LOCATIONS  HASH_LOCATIONS_COUNT)
    list(LENGTH HASH_NAMESPACES HASH_NAMESPACES_COUNT)

    foreach (HASH_LOCATION_INDEX RANGE ${HASH_LOCATIONS_COUNT})

        if (HASH_LOCATION_INDEX EQUAL ${HASH_LOCATIONS_COUNT})
        set(LOCATION "")
        else (HASH_LOCATION_INDEX EQUAL ${HASH_LOCATIONS_COUNT})
        list(GET HASH_LOCATIONS ${HASH_LOCATION_INDEX} LOCATION)
        endif (HASH_LOCATION_INDEX EQUAL ${HASH_LOCATIONS_COUNT})

    foreach (HASH_NAMESPACE_INDEX RANGE ${HASH_NAMESPACES_COUNT})

        if (HASH_NAMESPACE_INDEX EQUAL ${HASH_NAMESPACES_COUNT})
        set(NAMESPACE "")
        else (HASH_NAMESPACE_INDEX EQUAL ${HASH_NAMESPACES_COUNT})
        list(GET HASH_NAMESPACES ${HASH_NAMESPACE_INDEX} NAMESPACE)
        endif (HASH_NAMESPACE_INDEX EQUAL ${HASH_NAMESPACES_COUNT})

        set(HASH_SRC "
            #include <${LOCATION}hash_map>
            #include <${LOCATION}hash_set>
            int main ()
            {
              const ${NAMESPACE}::hash_map<int, int> hm;
              const ${NAMESPACE}::hash_set<int> hs;
              hm.find(1);
              hs.find(1);
              return 0;
            }")

        CHECK_CXX_SOURCE_COMPILES("${HASH_SRC}" HAVE_HASH_${HASH_LOCATION_INDEX}${HASH_NAMESPACE_INDEX})

        if (HAVE_HASH_${HASH_LOCATION_INDEX}${HASH_NAMESPACE_INDEX})
        set(HAVE_HASH_MAP TRUE)
        set(HAVE_HASH_SET TRUE)
        set(HASH_MAP_H "<${LOCATION}hash_map>")
        set(HASH_SET_H "<${LOCATION}hash_set>")
        set(HASH_MAP_CLASS "hash_map")
        set(HASH_SET_CLASS "hash_set")
        set(HASH_NAMESPACE ${NAMESPACE})
        break()
        endif (HAVE_HASH_${HASH_LOCATION_INDEX}${HASH_NAMESPACE_INDEX})

    endforeach (HASH_NAMESPACE_INDEX)

        if (HASH_NAMESPACE)
        break()
        endif (HASH_NAMESPACE)

    endforeach (HASH_LOCATION_INDEX)

    CHECK_INCLUDE_FILE(dlfcn.h     HAVE_DLFCN_H)
    CHECK_INCLUDE_FILE(fcntl.h     HAVE_FCNTL_H)
    CHECK_INCLUDE_FILE(inttypes.h  HAVE_INTTYPES_H)
    CHECK_INCLUDE_FILE(limits.h    HAVE_LIMITS_H)
    CHECK_INCLUDE_FILE(memory.h    HAVE_MEMORY_H)
    CHECK_INCLUDE_FILE(pthread.h   HAVE_PTHREAD)
    CHECK_INCLUDE_FILE(stdint.h    HAVE_STDINT_H)
    CHECK_INCLUDE_FILE(stdlib.h    HAVE_STDLIB_H)
    CHECK_INCLUDE_FILE(strings.h   HAVE_STRINGS_H)
    CHECK_INCLUDE_FILE(string.h    HAVE_STRING_H)
    CHECK_INCLUDE_FILE(sys/stat.h  HAVE_SYS_STAT_H)
    CHECK_INCLUDE_FILE(sys/types.h HAVE_SYS_TYPES_H)
    CHECK_INCLUDE_FILE(unistd.h    HAVE_UNISTD_H)
    CHECK_INCLUDE_FILE(zlib.h      HAVE_ZLIB)

    CHECK_FUNCTION_EXISTS(ftruncate HAVE_FTRUNCATE)
    CHECK_FUNCTION_EXISTS(memset    HAVE_MEMSET)
    CHECK_FUNCTION_EXISTS(mkdir     HAVE_MKDIR)
    CHECK_FUNCTION_EXISTS(strchr    HAVE_STRCHR)
    CHECK_FUNCTION_EXISTS(strerror  HAVE_STRERROR)
    CHECK_FUNCTION_EXISTS(strtol    HAVE_STRTOL)

    CHECK_SYMBOL_EXISTS(PTHREAD_CREATE_JOINABLE pthread.h HAVE_PTHREAD_CREATE_JOINABLE)
    if (NOT HAVE_PTHREAD_CREATE_JOINABLE)
        CHECK_SYMBOL_EXISTS(PTHREAD_CREATE_DETACHED pthread.h HAVE_PTHREAD_CREATE_DETACHED)
        if (HAVE_PTHREAD_CREATE_DETACHED)
        set(PTHREAD_CREATE_JOINABLE "PTHREAD_CREATE_DETACHED")
        endif (HAVE_PTHREAD_CREATE_DETACHED)
    endif (NOT HAVE_PTHREAD_CREATE_JOINABLE)

    if (HAVE_FCNTL_H AND HAVE_INTTYPES_H AND HAVE_LIMITS_H AND HAVE_STDLIB_H AND HAVE_UNISTD_H)
    set(STDC_HEADERS TRUE)
    endif (HAVE_FCNTL_H AND HAVE_INTTYPES_H AND HAVE_LIMITS_H AND HAVE_STDLIB_H AND HAVE_UNISTD_H)

    CHECK_SYMBOL_EXISTS(_AIX confdefs.h _ALL_SOURCE)

    set(_GNU_SOURCE TRUE)

    CHECK_INCLUDE_FILE(minix/config.h _MINIX)
    if (_MINIX)
    set(_POSIX_SOURCE   TRUE)
    set(_POSIX_1_SOURCE TRUE)
    endif (_MINIX)

    set(EXTENSIONS_SRC "#define __EXTENSIONS__ 1")
    set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <stdio.h>")

    if (HAVE_SYS_TYPES_H)
    set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <sys/types.h>")
    endif (HAVE_SYS_TYPES_H)

    if (HAVE_SYS_STAT_H)
    set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <sys/stat.h>")
    endif (HAVE_SYS_STAT_H)

    if (STDC_HEADERS)
    set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <stdlib.h>")
    set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <stddef.h>")
    else (STDC_HEADERS)
        if (HAVE_STDLIB_H)
        set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <stdlib.h>")
        endif (HAVE_STDLIB_H)
    endif (STDC_HEADERS)

    if (HAVE_STRING_H)
        if (NOT STDC_HEADERS AND HAVE_MEMORY_H)
        set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <memory.h>")
        endif (NOT STDC_HEADERS AND HAVE_MEMORY_H)
    set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <string.h>")
    endif (HAVE_STRING_H)

    if (HAVE_STRINGS_H)
    set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <strings.h>")
    endif (HAVE_STRINGS_H)

    if (HAVE_INTTYPES_H)
    set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <inttypes.h>")
    endif (HAVE_INTTYPES_H)

    if (HAVE_STDINT_H)
    set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <stdint.h>")
    endif (HAVE_STDINT_H)

    if (HAVE_UNISTD_H)
    set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\n#include <unistd.h>")
    endif (HAVE_UNISTD_H)

    set(EXTENSIONS_SRC "${EXTENSIONS_SRC}\nint main ()\n{\n  return 0;\n}\n")

    CHECK_CXX_SOURCE_COMPILES("${EXTENSIONS_SRC}" IS_SAFE_TO_DEFINE_EXTENSIONS)
    if (IS_SAFE_TO_DEFINE_EXTENSIONS)
    set(__EXTENSIONS__ TRUE)
    endif (IS_SAFE_TO_DEFINE_EXTENSIONS)

    set(_POSIX_PTHREAD_SEMANTICS TRUE)
    set(_TANDEM_SOURCE TRUE)

    configure_file(hdr/config.h.cmake ${PROJECT_BINARY_DIR}/../include/protobuf/config.h)

endif (MSVC)

aux_source_directory(src/google/protobuf          ${PROJECT_NAME}_SRC)
aux_source_directory(src/google/protobuf/compiler ${PROJECT_NAME}_SRC)
aux_source_directory(src/google/protobuf/io       ${PROJECT_NAME}_SRC)
aux_source_directory(src/google/protobuf/stubs    ${PROJECT_NAME}_SRC)

include_directories(${PROJECT_SOURCE_DIR}/include
                    ${PROJECT_BINARY_DIR}/../include/protobuf)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
add_definitions(-fPIC)
endif (CMAKE_SIZEOF_VOID_P EQUAL 8)

if (MSVC)
add_definitions(-W0)
add_definitions(-DLIBPROTOBUF_EXPORTS)
else (MSVC)
add_definitions(-w)
endif (MSVC)

add_library(${PROJECT_NAME} STATIC ${${PROJECT_NAME}_SRC})

if (HAVE_PTHREAD)
target_link_libraries(${PROJECT_NAME} pthread)
endif (HAVE_PTHREAD)

if (HAVE_ZLIB)
target_link_libraries(${PROJECT_NAME} z)
endif (HAVE_ZLIB)

message(STATUS "Target '${PROJECT_NAME}' is configured")
message("---------------------------------------------")
