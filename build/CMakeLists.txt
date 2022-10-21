cmake_minimum_required(VERSION 3.7)

if(${CMAKE_VERSION} VERSION_LESS 3.22)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
else()
  cmake_policy(VERSION 3.22)
endif()

#set(CMAKE_VERBOSE_MAKEFILE on) # for debugging

# Paths
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules")
set(CMAKE_SOURCE_DIR "..")

set(PBOTED_SRC_DIR ${CMAKE_SOURCE_DIR}/src)

include(Version)
set_version("${PBOTED_SRC_DIR}/version.h" PROJECT_VERSION)

project(
    pboted
    LANGUAGES C CXX
    VERSION ${PROJECT_VERSION})

# Configuration options
option(WITH_STATIC "Static build"         OFF)
# ToDo?
#option(WITH_CLANG  "Force Clang compiler" OFF)
#if (WITH_CLANG)
#    set (CMAKE_C_COMPILER "/usr/bin/clang")
#    set (CMAKE_CXX_COMPILER "/usr/bin/clang++")
#endif ()

# Handle paths nicely
include(GNUInstallDirs)

include(ExternalProject)

# Architecture
include(TargetArch)
target_architecture(ARCHITECTURE)

include(CheckAtomic)

# libi2pd stuff
set(LIBI2PD_SRC_DIR ${CMAKE_SOURCE_DIR}/lib/libi2pd)
include_directories(${LIBI2PD_SRC_DIR})
file(GLOB LIBI2PD_SRC ${LIBI2PD_SRC_DIR}/*.cpp)
add_library(libi2pd ${LIBI2PD_SRC})
set_target_properties(libi2pd PROPERTIES PREFIX "")

# libi2psam stuff
set(LIBI2PSAM_SRC_DIR ${CMAKE_SOURCE_DIR}/lib/i2psam)
include_directories(${LIBI2PSAM_SRC_DIR})
file(GLOB LIBI2PSAM_SRC ${LIBI2PSAM_SRC_DIR}/*.cpp)
add_library(libi2psam ${LIBI2PSAM_SRC})
set_target_properties(libi2psam PROPERTIES PREFIX "")

# liblzma stuff
set(LIBLZMA_SRC_DIR ${CMAKE_SOURCE_DIR}/lib/lzma)
set_source_files_properties(${LIBLZMA_SRC_DIR} PROPERTIES LANGUAGE C)
include_directories(${LIBLZMA_SRC_DIR})
file(GLOB LIBLZMA_SRC ${LIBLZMA_SRC_DIR}/*.c)
add_library(liblzma ${LIBLZMA_SRC})
set_target_properties(liblzma PROPERTIES PREFIX "")

# pboted stuff
include_directories(${PBOTE_SRC_DIR})
file(GLOB PBOTED_SRC ${PBOTED_SRC_DIR}/*.cpp)

# Compiler flags customization (by vendor)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra -Winvalid-pch -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS_DEBUG "-g -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pedantic")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -flto -s -ffunction-sections -fdata-sections")
set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "-Wl,--gc-sections") # -flto is added from above

# Check for C++17 support
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++17" CXX17_SUPPORTED)
if (CXX17_SUPPORTED)
    set (CMAKE_CXX_STANDARD 17)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
else ()
    message(SEND_ERROR "C++17 standard not seems to be supported by compiler. Too old version?")
endif ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # more tweaks
    if (LINUX)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -stdlib=libstdc++") # required for <atomic>
        list(APPEND CMAKE_REQUIRED_LIBRARIES "stdc++") # required to link with -stdlib=libstdc++
    endif ()
    if (NOT (MSVC OR MSYS OR APPLE))
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-const-variable -Wno-overloaded-virtual -Wno-c99-extensions")
    endif ()
endif ()

# Compiler flags customization (by system)
if (NOT (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR APPLE))
    # "'sleep_for' is not a member of 'std::this_thread'" in gcc 4.7/4.8
    add_definitions("-D_GLIBCXX_USE_NANOSLEEP=1")
endif ()

# Libraries
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
if (THREADS_HAVE_PTHREAD_ARG) # compile time flag
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif ()

if (WITH_STATIC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_USE_STATIC_RUNTIME ON)

    set(ZLIB_USE_STATIC_LIBS ON)
    set(ZLIB_NAMES zlibstatic zlibstat zlib z)

    set(MIMETIC_USE_STATIC_LIBS ON)

    set(BUILD_STATIC_LIBS ON)
    set(BUILD_SHARED_LIBS OFF)
endif ()

find_package(Boost COMPONENTS program_options REQUIRED)
if (NOT Boost_FOUND)
    message(SEND_ERROR "Boost is not found. Please download and install it first!")
endif ()

find_package(OpenSSL REQUIRED)
if (NOT OPENSSL_FOUND)
    message(SEND_ERROR "Could not find OpenSSL. Please download and install it first!")
endif ()

find_package(ZLIB REQUIRED)
if (NOT ZLIB_FOUND)
    message(SEND_ERROR "Could not find ZLIB. Please download and install it first!")
endif ()

find_package(Mimetic REQUIRED)
if(NOT MIMETIC_FOUND)
    message(SEND_ERROR "Could not find Mimetic. Please download and install it first!")
endif()

if (WITH_STATIC)
    if (${CMAKE_CXX_COMPILER} MATCHES ".*-openwrt-.*")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
        #set(CMAKE_THREAD_LIBS_INIT "gcc_eh -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
        set(CMAKE_THREAD_LIBS_INIT
            "gcc_eh -Wl,-u,pthread_create,-u,pthread_once,-u,pthread_mutex_lock,
            -u,pthread_mutex_unlock,-u,pthread_join,-u,pthread_equal,
            -u,pthread_detach,-u,pthread_cond_wait,-u,pthread_cond_signal,
            -u,pthread_cond_destroy,-u,pthread_cond_broadcast,-u,pthread_cancel")
    endif ()
else ()
    # No need in -fPIC overhead for binary if not interested in library
    # HINT: revert c266cff CMakeLists.txt: compilation speed up
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    add_definitions(-DBOOST_PROGRAM_OPTIONS_DYN_LINK)
endif ()

# Load includes
include_directories(SYSTEM
                    ${MIMETIC_INCLUDE_DIRS}
                    ${Boost_INCLUDE_DIRS}
                    ${OPENSSL_INCLUDE_DIR}
                    ${ZLIB_INCLUDE_DIRS})

# Show summary
message(STATUS "Project            : ${PROJECT_NAME}")
message(STATUS "Version            : ${PROJECT_VERSION}")
message(STATUS "----------------------------------------")
message(STATUS "Build type         : ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler vendor    : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler version   : ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "C compiler path    : ${CMAKE_C_COMPILER}")
message(STATUS "C++ compiler path  : ${CMAKE_CXX_COMPILER}")
message(STATUS "C++ standard       : ${CMAKE_CXX_STANDARD}")
message(STATUS "Architecture       : ${ARCHITECTURE}")
message(STATUS "Install prefix     : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Options:")
message(STATUS "  STATIC BUILD     : ${WITH_STATIC}")
message(STATUS "----------------------------------------")

add_executable("${PROJECT_NAME}" ${PBOTED_SRC})

if (NOT MSVC)
    if (WITH_STATIC)
        set_target_properties("${PROJECT_NAME}" PROPERTIES LINK_FLAGS "-static")
    endif ()
endif ()

# FindBoost pulls pthread for thread which is broken
# for static linking at least on Ubuntu 15.04
list(GET Boost_LIBRARIES -1 LAST_Boost_LIBRARIES)
if (${LAST_Boost_LIBRARIES} MATCHES ".*pthread.*")
    list(REMOVE_AT Boost_LIBRARIES -1)
endif ()

if (WITH_STATIC)
    set(DL_LIB ${CMAKE_DL_LIBS})
endif ()

set(LIBS
    libi2pd
    libi2psam
    liblzma
    Threads::Threads
    ${ZLIB_LIBRARIES}
    ${MIMETIC_LIBRARIES}
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${MINGW_EXTRA}
    ${DL_LIB}
    ${CMAKE_REQUIRED_LIBRARIES})

# If GCC version is less than 9
# we need to link filesystem manually
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if (NOT (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 9.0))
        list(APPEND LIBS libstdc++fs)
    endif ()
endif ()

target_link_libraries("${PROJECT_NAME}" ${LIBS})
