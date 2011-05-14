@echo off

del /f CMakeCache.txt

cmake.exe ^
    -D BOOST_ROOT="C:\Program Files\Boost" ^
    -G "Visual Studio 9 2008" .
