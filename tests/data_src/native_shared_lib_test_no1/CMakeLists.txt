cmake_minimum_required(VERSION 3.15)


project(native_shared_lib_test_no1
    LANGUAGES CXX)

include(GNUInstallDirs)
if(NOT DEFINED CMAKE_MACOSX_RPATH)
    set(CMAKE_MACOSX_RPATH ON)
endif()
if(APPLE)
    set(baseDir @loader_path)
else()
    set(baseDir $ORIGIN)
endif()
file(RELATIVE_PATH relDir "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}" "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
list(APPEND CMAKE_INSTALL_RPATH "${baseDir}" "${baseDir}/${relDir}")

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

add_library(testlib SHARED
    lib/testlib.cpp
    lib/testlib.hpp
    )

add_executable(hello_world hello_world.cpp)

target_link_libraries(hello_world PUBLIC testlib)

install(TARGETS hello_world testlib)
