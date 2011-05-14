#!/bin/bash

rm -f CMakeCache.txt

cmake \
    -D CMAKE_BUILD_TYPE=$1 \
    -G "Unix Makefiles" .

exit 0
