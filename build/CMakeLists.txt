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
option(CONTROL_SOCKET "Use UNIX socket in control module" ON)
option(WITH_STATIC    "Static build"                      OFF)
option(WITH_CXX11     "Force C++11"                       OFF)
option(WITH_CXX17     "Force C++17"                       OFF)
# ToDo?
#option(WITH_CLANG  "Force Clang compiler" OFF)
#if (WITH_CLANG)
#  set (CMAKE_C_COMPILER "/usr/bin/clang")
#  set (CMAKE_CXX_COMPILER "/usr/bin/clang++")
#endif ()

# Windows-only options
if (MSYS)
  option(WITH_UI      "Static build"                      ON)
endif ()

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
include_directories(${PBOTED_SRC_DIR})
file(GLOB PBOTED_SRC ${PBOTED_SRC_DIR}/*.cpp)

if (MSYS)
  set(CMAKE_RC_COMPILER_INIT windres)
  ENABLE_LANGUAGE(RC)
  SET(CMAKE_RC_COMPILE_OBJECT
      "<CMAKE_RC_COMPILER> <FLAGS> -O coff <DEFINES> -i <SOURCE> -o <OBJECT>")

  set(WIN32_SRC_DIR ${PBOTED_SRC_DIR}/win32)
  file(GLOB WIN32_RC ${WIN32_SRC_DIR}/*.rc)

  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWIN32 -DWIN32_LEAN_AND_MEAN")
endif ()

# Compiler flags customization (by vendor)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Winvalid-pch -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pedantic")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -flto -s -ffunction-sections -fdata-sections")
set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "-Wl,--gc-sections") # -flto is added from above

if (NOT CONTROL_SOCKET)
  add_definitions("-DDISABLE_SOCKET=1")
endif ()

# Check for C++11 or C++17 support
include(CheckCXXCompilerFlag)

CHECK_CXX_COMPILER_FLAG("-std=c++11" CXX11_SUPPORTED)
CHECK_CXX_COMPILER_FLAG("-std=c++17" CXX17_SUPPORTED)

if (WITH_CXX11 AND WITH_CXX17)
  message(SEND_ERROR "WITH_CXX11 and WITH_CXX17 mutually exclusive options")
endif ()

if (WITH_CXX11)
  if (CXX11_SUPPORTED)
    set (CMAKE_CXX_STANDARD 11)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
  else ()
    message(SEND_ERROR "C++11 standard not seems to be supported by compiler. Too old version?")
  endif ()
elseif (WITH_CXX17)
  if (CXX17_SUPPORTED)
    set (CMAKE_CXX_STANDARD 17)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
  else ()
    message(SEND_ERROR "C++17 standard not seems to be supported by compiler. Too old version?")
  endif ()
else ()
  if(CXX17_SUPPORTED)
    set (CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
  elseif(CXX11_SUPPORTED)
    set (CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
  else()
    message(SEND_ERROR "C++17 nor C++11 standard not seems to be supported by compiler. Too old version?")
  endif()
endif ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  # more tweaks
  if (LINUX)
    # Required for <atomic>
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -stdlib=libstdc++")
    # Required to link with -stdlib=libstdc++
    list(APPEND CMAKE_REQUIRED_LIBRARIES "stdc++")
  endif ()
  if (NOT (MSVC OR MSYS OR APPLE))
    set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} -Wno-unused-const-variable -Wno-overloaded-virtual \
        -Wno-c99-extensions")
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

  set(Boost_USE_STATIC_LIBS    ON)
  set(Boost_USE_RELEASE_LIBS   ON)
  set(Boost_USE_STATIC_RUNTIME OFF)

  set(OPENSSL_USE_STATIC_LIBS ON)

  set(ZLIB_USE_STATIC_LIBS ON)
  set(ZLIB_NAMES libz zlibstatic zlibstat zlib z)
  #set(ZLIB_NAMES_DEBUG zlibstaticd zlibstatd)

  set(MIMETIC_USE_STATIC_LIBS ON)

  #set(BUILD_STATIC_LIBS ON)
  #set(BUILD_SHARED_LIBS OFF)
endif ()

if (CMAKE_CXX_STANDARD LESS 17)
  find_package(Boost COMPONENTS system filesystem program_options REQUIRED)
  if (NOT Boost_FOUND)
    message(SEND_ERROR
            "Boost is not found. Please download and install it first!")
  endif ()
else ()
  find_package(Boost COMPONENTS program_options REQUIRED)
  if (NOT Boost_FOUND)
    message(SEND_ERROR
            "Boost is not found. Please download and install it first!")
  endif ()
endif ()

find_package(OpenSSL REQUIRED)
if (NOT OPENSSL_FOUND)
  message(SEND_ERROR
          "Could not find OpenSSL. Please download and install it first!")
endif ()

find_package(ZLIB REQUIRED)
if (NOT ZLIB_FOUND)
  message(SEND_ERROR
          "Could not find ZLIB. Please download and install it first!")
endif ()

find_package(Mimetic REQUIRED)
if(NOT MIMETIC_FOUND)
  message(SEND_ERROR
          "Could not find Mimetic. Please download and install it first!")
endif()

if (WITH_STATIC)
  if (CMAKE_CXX_STANDARD LESS 17)
    add_definitions(-DBOOST_FILESYSTEM_STATIC_LINK)
    add_definitions(-DBOOST_PROGRAM_OPTIONS_STATIC_LINK)
    add_definitions(-DBOOST_SYSTEM_STATIC_LINK)
  else ()
    add_definitions(-DBOOST_PROGRAM_OPTIONS_STATIC_LINK)
  endif ()
  if (${CMAKE_CXX_COMPILER} MATCHES ".*-openwrt-.*")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
    #set(CMAKE_THREAD_LIBS_INIT
    #    "gcc_eh -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
    set(CMAKE_THREAD_LIBS_INIT
      "gcc_eh -Wl,-u,pthread_create,-u,pthread_once,-u,pthread_mutex_lock, \
      -u,pthread_mutex_unlock,-u,pthread_join,-u,pthread_equal, \
      -u,pthread_detach,-u,pthread_cond_wait,-u,pthread_cond_signal, \
      -u,pthread_cond_destroy,-u,pthread_cond_broadcast,-u,pthread_cancel")
  endif ()
else ()
  # No need in -fPIC overhead for binary if not interested in library
  # HINT: revert c266cff CMakeLists.txt: compilation speed up
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
  if (CMAKE_CXX_STANDARD LESS 17)
    add_definitions(-DBOOST_FILESYSTEM_DYN_LINK)
    add_definitions(-DBOOST_PROGRAM_OPTIONS_DYN_LINK)
    add_definitions(-DBOOST_SYSTEM_DYN_LINK)
  else ()
    add_definitions(-DBOOST_PROGRAM_OPTIONS_DYN_LINK)
  endif ()
endif ()

# Load includes
set(INCLUDED_DIRS
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
    ${MIMETIC_INCLUDE_DIRS})

# After migrating to CLI11
#if (CMAKE_CXX_STANDARD LESS 17)
#  list(APPEND INCLUDED_DIRS ${Boost_INCLUDE_DIRS})
#endif ()

include_directories(SYSTEM ${INCLUDED_DIRS})

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
message(STATUS "  UNIX SOCKET      : ${CONTROL_SOCKET}")
message(STATUS "  FORCE C++11      : ${WITH_CXX11}")
message(STATUS "  FORCE C++17      : ${WITH_CXX17}")
if (MSYS)
  message(STATUS "  Tray UI          : ${WITH_UI}")
endif()

message(STATUS "----------------------------------------")

if (MSYS)
  if (WITH_UI)
    add_executable("${PROJECT_NAME}" WIN32 ${PBOTED_SRC} ${WIN32_RC})
  else ()
    add_executable("${PROJECT_NAME}" ${PBOTED_SRC} ${WIN32_RC})
  endif ()
else ()
  add_executable("${PROJECT_NAME}" ${PBOTED_SRC})
endif ()

if (NOT MSVC)
  if (MSYS)
    set(MINGW_EXTRA
        "wsock32"
        "ws2_32"
        "iphlpapi"
    )


    # Strip debug symbols to file only on release build
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                       DEPENDS "${PROJECT_NAME}"
                       COMMAND $<$<CONFIG:Release>:${CMAKE_OBJCOPY}>
                       ARGS --only-keep-debug $<TARGET_FILE:${PROJECT_NAME}> $<TARGET_FILE:${PROJECT_NAME}>.debug)

    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                       DEPENDS "${PROJECT_NAME}"
                       COMMAND $<$<CONFIG:Release>:${CMAKE_STRIP}>
                       ARGS $<TARGET_FILE:${PROJECT_NAME}>)
  endif ()

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

if (CMAKE_CXX_STANDARD LESS 17)
  set(PBOTED_BOOST_Libs Boost::system Boost::filesystem Boost::program_options)
else ()
  set(PBOTED_BOOST_Libs Boost::program_options )
endif ()

set(LINK_LIBS
  libi2pd
  libi2psam
  liblzma
  ${MIMETIC_LIBRARIES}
  ${PBOTED_BOOST_Libs}
  OpenSSL::SSL
  OpenSSL::Crypto
  ZLIB::ZLIB
  Threads::Threads
  ${MINGW_EXTRA}
  ${DL_LIB}
  ${CMAKE_REQUIRED_LIBRARIES})

# If GCC version is less than 9 we need to link filesystem manually
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0 AND CMAKE_CXX_STANDARD EQUAL 17)
    list(APPEND LINK_LIBS stdc++fs)
  endif ()
endif ()

target_link_libraries("${PROJECT_NAME}" ${LINK_LIBS})
