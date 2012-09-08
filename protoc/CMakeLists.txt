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

project(protoc)
cmake_minimum_required(VERSION 2.6)

if (MSVC)
set(${PROJECT_NAME}_SRC src/google/protobuf/compiler/main.cc)
else (MSVC)
aux_source_directory(src/google/protobuf/compiler        ${PROJECT_NAME}_SRC)
aux_source_directory(src/google/protobuf/compiler/cpp    ${PROJECT_NAME}_SRC)
aux_source_directory(src/google/protobuf/compiler/java   ${PROJECT_NAME}_SRC)
aux_source_directory(src/google/protobuf/compiler/python ${PROJECT_NAME}_SRC)
endif (MSVC)

include_directories(${PROJECT_SOURCE_DIR}/../include
                    ${PROJECT_BINARY_DIR}/../include/protobuf)

link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

if (MSVC)
add_definitions(-W0)
else (MSVC)
add_definitions(-w)
endif (MSVC)

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SRC})
add_dependencies(${PROJECT_NAME} protobuf)
target_link_libraries(${PROJECT_NAME} protobuf)

if (HAVE_PTHREAD)
target_link_libraries(${PROJECT_NAME} pthread)
endif (HAVE_PTHREAD)

message(STATUS "Target '${PROJECT_NAME}' is configured")
message("---------------------------------------------")

if (MSVC)

    project(libprotoc)
    cmake_minimum_required(VERSION 2.6)

    set(${PROJECT_NAME}_SRC
        src/google/protobuf/compiler/code_generator.cc
        src/google/protobuf/compiler/command_line_interface.cc
        src/google/protobuf/compiler/plugin.cc
        src/google/protobuf/compiler/plugin.pb.cc
        src/google/protobuf/compiler/subprocess.cc
        src/google/protobuf/compiler/zip_writer.cc)

    aux_source_directory(src/google/protobuf/compiler/cpp    ${PROJECT_NAME}_SRC)
    aux_source_directory(src/google/protobuf/compiler/java   ${PROJECT_NAME}_SRC)
    aux_source_directory(src/google/protobuf/compiler/python ${PROJECT_NAME}_SRC)

    add_definitions(-DLIBPROTOC_EXPORTS)

    add_library(${PROJECT_NAME} STATIC ${${PROJECT_NAME}_SRC})
    add_dependencies(${PROJECT_NAME} protobuf)
    target_link_libraries(${PROJECT_NAME} protobuf)

    add_dependencies(protoc ${PROJECT_NAME})
    target_link_libraries(protoc ${PROJECT_NAME})

    message(STATUS "Target '${PROJECT_NAME}' is configured")
    message("---------------------------------------------")

endif (MSVC)
