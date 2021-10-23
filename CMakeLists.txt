cmake_minimum_required(VERSION 3.10)
project(pbote VERSION 0.7.1)

# for debugging
#set(CMAKE_VERBOSE_MAKEFILE on)

# configurale options
option(WITH_BINARY "Build binary" ON)
option(WITH_STATIC "Static build" OFF)

# paths
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/build/cmake_modules")
set(CMAKE_SOURCE_DIR "")

#Handle paths nicely
include(GNUInstallDirs)

# architecture
include(TargetArch)
target_architecture(ARCHITECTURE)

set(LIBLZMA_SRC_DIR lib/lzma)
set(PBOTE_SRC_DIR src)

add_subdirectory(lib/libi2pd)
add_subdirectory(lib/sam)

include_directories(${LIBLZMA_SRC_DIR})
include_directories(${PBOTE_SRC_DIR})

FILE(GLOB LIBLZMA_SRC ${LIBLZMA_SRC_DIR}/*.c)
add_library(liblzma ${LIBLZMA_SRC})
set_target_properties(liblzma PROPERTIES PREFIX "")

set(PBOTE_SRC
        "${PBOTE_SRC_DIR}/pboted.cpp"
        "${PBOTE_SRC_DIR}/AddressBook.cpp"
        "${PBOTE_SRC_DIR}/BoteContext.cpp"
        "${PBOTE_SRC_DIR}/ConfigParser.cpp"
        "${PBOTE_SRC_DIR}/Cryptography.cpp"
        "${PBOTE_SRC_DIR}/BoteDaemon.cpp"
        "${PBOTE_SRC_DIR}/DHTworker.cpp"
        "${PBOTE_SRC_DIR}/DHTStorage.cpp"
        "${PBOTE_SRC_DIR}/Email.cpp"
        "${PBOTE_SRC_DIR}/EmailIdentity.cpp"
        "${PBOTE_SRC_DIR}/EmailWorker.cpp"
        "${PBOTE_SRC_DIR}/FileSystem.cpp"
        "${PBOTE_SRC_DIR}/Logging.cpp"
        "${PBOTE_SRC_DIR}/NetworkWorker.cpp"
        "${PBOTE_SRC_DIR}/PacketHandler.cpp"
        "${PBOTE_SRC_DIR}/POP3.cpp"
        "${PBOTE_SRC_DIR}/RelayPeersWorker.cpp"
        "${PBOTE_SRC_DIR}/SMTP.cpp"
        "${PBOTE_SRC_DIR}/UnixDaemon.cpp"
        )

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
# TODO: once CMake 3.1+ becomes mainstream, see e.g. http://stackoverflow.com/a/29871891/673826
# use imported Threads::Threads instead
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
        # set( CMAKE_THREAD_LIBS_INIT "gcc_eh -Wl,--whole-archive -lpthread -Wl,--no-whole-archive" )
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

# ToDo: add to sources with cmake
add_library(mimetic SHARED IMPORTED) # or STATIC instead of SHARED
set_target_properties(mimetic PROPERTIES
        IMPORTED_LOCATION "/usr/local/lib/libmimetic.so"
        INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include/mimetic"
        )

# load includes
include_directories(SYSTEM ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR})

#include(CheckAtomic)

# show summary
message(STATUS "---------------------------------------")
message(STATUS "Build type         : ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler vendor    : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler version   : ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Compiler path      : ${CMAKE_CXX_COMPILER}")
message(STATUS "Architecture       : ${ARCHITECTURE}")
message(STATUS "Install prefix:    : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Options:")
message(STATUS "  BINARY           : ${WITH_BINARY}")
message(STATUS "  STATIC BUILD     : ${WITH_STATIC}")
message(STATUS "---------------------------------------")

#Handle paths nicely
include(GNUInstallDirs)

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

    target_link_libraries("${PROJECT_NAME}" libi2pd liblzma libsam mimetic ${DL_LIB} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES}
            ${ZLIB_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ${MINGW_EXTRA} ${DL_LIB} ${CMAKE_REQUIRED_LIBRARIES})

    #install(TARGETS "${PROJECT_NAME}" RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime)
    #set(APPS "\${CMAKE_INSTALL_PREFIX}/bin/${PROJECT_NAME}${CMAKE_EXECUTABLE_SUFFIX}")
    #set(DIRS "${Boost_LIBRARY_DIR};${OPENSSL_INCLUDE_DIR}/../bin;/mingw32/bin")
endif ()

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "pboted, a C++ secure mail daemon")
set(CPACK_PACKAGE_VENDOR "Purple Bote")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
file(READ src/version.h version_hpp)
string(REGEX REPLACE ".*PBOTE_VERSION_MAJOR ([0-9]+).*" "\\1" CPACK_PACKAGE_VERSION_MAJOR "${version_hpp}")
string(REGEX REPLACE ".*PBOTE_VERSION_MINOR ([0-9]+).*" "\\1" CPACK_PACKAGE_VERSION_MINOR "${version_hpp}")
string(REGEX REPLACE ".*PBOTE_VERSION_MICRO ([0-9]+).*" "\\1" CPACK_PACKAGE_VERSION_MICRO "${version_hpp}")
string(REGEX REPLACE ".*PBOTE_VERSION_PATCH ([0-9]+).*" "\\1" CPACK_PACKAGE_VERSION_PATCH "${version_hpp}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "Purple Bote")# ${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}")
include(CPackComponent)
cpack_add_component(Runtime
        DESCRIPTION "Main files"
        REQUIRED INSTALL_TYPES minimal)
cpack_add_component(Symbols
        DISPLAY_NAME "Debug symbols"
        DESCRIPTION "Debug symbols for use with WinDbg or Visual Studio"
        INSTALL_TYPES recommended full
        )
cpack_add_component(Libraries
        DESCRIPTION "Binary libraries for development"
        INSTALL_TYPES full dev3rd
        )
cpack_add_component(Source
        DISPLAY_NAME "Source code"
        DESCRIPTION "I2pd source code"
        INSTALL_TYPES full
        )
cpack_add_component(Headers
        DISPLAY_NAME "Header files"
        DESCRIPTION "I2pd header files for development"
        INSTALL_TYPES full dev3rd
        )
cpack_add_install_type(recommended DISPLAY_NAME Recommended)
cpack_add_install_type(dev3rd DISPLAY_NAME "Third party development")
cpack_add_install_type(full DISPLAY_NAME Full)
cpack_add_install_type(minimal DISPLAY_NAME Minimal)
set(CPACK_STRIP_FILES "bin/pbote")
set(CPACK_SOURCE_STRIP_FILES "")
set(CPACK_PACKAGE_EXECUTABLES "pbote" "C++ secure mail daemon")
set(CPACK_SOURCE_GENERATOR "TGZ")
include(CPack)
