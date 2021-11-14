cmake_minimum_required(VERSION 3.7)
project("pboted")

#set(CMAKE_VERBOSE_MAKEFILE on) # for debugging

# configurale options
option(WITH_BINARY "Build binary" ON)
option(WITH_STATIC "Static build" OFF)

# paths
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules")
set(CMAKE_SOURCE_DIR "..")

#Handle paths nicely
include(GNUInstallDirs)

include(ExternalProject)

# architecture
include(TargetArch)
target_architecture(ARCHITECTURE)

set(LIBI2PD_SRC_DIR ${CMAKE_SOURCE_DIR}/lib/i2pd/libi2pd)
set(I2PSAM_SRC_DIR ${CMAKE_SOURCE_DIR}/lib/i2psam)
set(LIBLZMA_SRC_DIR ${CMAKE_SOURCE_DIR}/lib/lzma)
set(PBOTE_SRC_DIR ${CMAKE_SOURCE_DIR}/src)

include_directories(${LIBI2PD_SRC_DIR})
include_directories(${I2PSAM_SRC_DIR})
include_directories(${LIBLZMA_SRC_DIR})
include_directories(${PBOTE_SRC_DIR})

FILE(GLOB LIBI2PD_SRC ${LIBI2PD_SRC_DIR}/*.cpp)
add_library(libi2pd ${LIBI2PD_SRC})
set_target_properties(libi2pd PROPERTIES PREFIX "")

FILE(GLOB I2PSAM_SRC ${I2PSAM_SRC_DIR}/*.cpp)
add_library(i2psam ${I2PSAM_SRC})
set_target_properties(i2psam PROPERTIES PREFIX "")

FILE(GLOB LIBLZMA_SRC ${LIBLZMA_SRC_DIR}/*.c)
add_library(liblzma ${LIBLZMA_SRC})
set_target_properties(liblzma PROPERTIES PREFIX "")

FILE(GLOB PBOTE_SRC ${PBOTE_SRC_DIR}/*.cpp)

# compiler flags customization (by vendor)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Winvalid-pch -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pedantic")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -flto -s -ffunction-sections -fdata-sections")
set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "-Wl,--gc-sections") # -flto is added from above

# check for c++17 & c++11 support
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++17" CXX17_SUPPORTED)
CHECK_CXX_COMPILER_FLAG("-std=c++11" CXX11_SUPPORTED)
if (CXX17_SUPPORTED)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
elseif (CXX11_SUPPORTED)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else ()
    message(SEND_ERROR "C++17 nor C++11 standard not seems to be supported by compiler. Too old version?")
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

# compiler flags customization (by system)
if (NOT (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR APPLE))
    # "'sleep_for' is not a member of 'std::this_thread'" in gcc 4.7/4.8
    add_definitions("-D_GLIBCXX_USE_NANOSLEEP=1")
endif ()

# libraries
set(THREADS_PREFER_PTHREAD_FLAG ON)
if (IOS)
    set(CMAKE_THREAD_LIBS_INIT "-lpthread")
    set(CMAKE_HAVE_THREADS_LIBRARY 1)
    set(CMAKE_USE_WIN32_THREADS_INIT 0)
    set(CMAKE_USE_PTHREADS_INIT 1)
else ()
    find_package(Threads REQUIRED)
endif ()
if (THREADS_HAVE_PTHREAD_ARG) # compile time flag
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif ()

if (WITH_STATIC)
    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_USE_STATIC_RUNTIME ON)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
    set(BUILD_SHARED_LIBS OFF)
    if (${CMAKE_CXX_COMPILER} MATCHES ".*-openwrt-.*")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
        #set(CMAKE_THREAD_LIBS_INIT "gcc_eh -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
        set(CMAKE_THREAD_LIBS_INIT "gcc_eh -Wl,-u,pthread_create,-u,pthread_once,-u,pthread_mutex_lock,-u,pthread_mutex_unlock,-u,pthread_join,-u,pthread_equal,-u,pthread_detach,-u,pthread_cond_wait,-u,pthread_cond_signal,-u,pthread_cond_destroy,-u,pthread_cond_broadcast,-u,pthread_cancel")
    endif ()
else ()
    # No need in -fPIC overhead for binary if not interested in library
    # HINT: revert c266cff CMakeLists.txt: compilation speed up
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    add_definitions(-DBOOST_SYSTEM_DYN_LINK -DBOOST_FILESYSTEM_DYN_LINK -DBOOST_PROGRAM_OPTIONS_DYN_LINK -DBOOST_DATE_TIME_DYN_LINK -DBOOST_REGEX_DYN_LINK)
endif ()

find_package(Boost COMPONENTS system filesystem program_options date_time thread REQUIRED)
if (NOT DEFINED Boost_INCLUDE_DIRS)
    message(SEND_ERROR "Boost is not found, or your boost version was below 1.46. Please download Boost!")
endif ()

find_package(OpenSSL REQUIRED)
if (NOT DEFINED OPENSSL_INCLUDE_DIR)
    message(SEND_ERROR "Could not find OpenSSL. Please download and install it first!")
endif ()

find_package(ZLIB)
if (ZLIB_FOUND)
    link_directories(${ZLIB_ROOT}/lib)
endif ()

find_package(Mimetic REQUIRED)
if(NOT MIMETIC_FOUND)
  message(SEND_ERROR "Could not find Mimetic. Please download and install it first!")
endif()

find_program(MAKE_EXE NAMES make)

# load includes
include_directories(SYSTEM ${MIMETIC_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR})

include(CheckAtomic)

# show summary
message(STATUS "----------------------------------------")
message(STATUS "Build type         : ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler vendor    : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler version   : ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Compiler path      : ${CMAKE_CXX_COMPILER}")
message(STATUS "Architecture       : ${ARCHITECTURE}")
message(STATUS "Install prefix     : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Options:")
message(STATUS "  BINARY           : ${WITH_BINARY}")
message(STATUS "  STATIC BUILD     : ${WITH_STATIC}")
message(STATUS "----------------------------------------")

if (WITH_BINARY)
    add_executable("${PROJECT_NAME}" ${PBOTE_SRC})

    if (NOT MSVC)
        if (WITH_STATIC)
            set_target_properties("${PROJECT_NAME}" PROPERTIES LINK_FLAGS "-static")
        endif ()
    endif ()

    # FindBoost pulls pthread for thread which is broken for static linking at least on Ubuntu 15.04
    list(GET Boost_LIBRARIES -1 LAST_Boost_LIBRARIES)
    if (${LAST_Boost_LIBRARIES} MATCHES ".*pthread.*")
        list(REMOVE_AT Boost_LIBRARIES -1)
    endif ()

    if (WITH_STATIC)
        set(DL_LIB ${CMAKE_DL_LIBS})
    endif ()

    target_link_libraries("${PROJECT_NAME}" libi2pd i2psam liblzma Threads::Threads ${MIMETIC_LIBRARIES}
            ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARY} ${MINGW_EXTRA} ${DL_LIB} ${CMAKE_REQUIRED_LIBRARIES})
    install(TARGETS "${PROJECT_NAME}" RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime)
    set(APPS "\${CMAKE_INSTALL_PREFIX}/bin/${PROJECT_NAME}${CMAKE_EXECUTABLE_SUFFIX}")
    set(DIRS "${MIMETIC_INCLUDE_DIRS}${Boost_LIBRARY_DIR};${OPENSSL_INCLUDE_DIR}/../bin;${ZLIB_INCLUDE_DIR}/../bin;/mingw32/bin")
endif ()
