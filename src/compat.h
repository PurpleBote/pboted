/**
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#pragma once
#ifndef BOTE_SRC_COMPATH_H
#define BOTE_SRC_COMPATH_H

/**
 * Start of Network stuff
 */
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <wspiapi.h>
  #include <mstcpip.h>
  #include <afunix.h>

  #define MSG_DONTWAIT 0

  #define PB_INT_OR_DWORD DWORD
  #define PB_SOCKET_ERROR SOCKET_ERROR
  #define PB_SOCKET_INVALID INVALID_SOCKET
  #define PB_SOCKET_CLOSE closesocket
  #define PB_SOCKET_POLL WSAPoll
  #define PB_SOCKET_READ(a,b,c) recv(a, b, c, 0)
  #define PB_SOCKET_WRITE(a,b,c) send(a, b, c, 0)
  #define PB_SOCKET_IOCTL(a,b,c) ioctlsocket(a, b, &c)
#else
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <poll.h>
  #include <sys/ioctl.h>
  #include <sys/select.h>
  #include <sys/socket.h>

  #define PB_INT_OR_DWORD int
  #define PB_SOCKET_ERROR -1
  #define PB_SOCKET_INVALID -1
  #define PB_SOCKET_CLOSE close
  #define PB_SOCKET_POLL poll
  #define PB_SOCKET_READ read
  #define PB_SOCKET_WRITE write
  #define PB_SOCKET_IOCTL(a,b,c) ioctl(a, b, (char *)&c)
#endif


//#ifndef INVALID_SOCKET
//#define INVALID_SOCKET -1
//#endif

/* For comparation without just rc == -1 */
enum common_rc
{
  RC_ERROR = -1,
  RC_SUCCESS = 0,
};

enum select_rc
{
  SELECT_ERROR = -1,
  SELECT_TIMEOUT = 0,
};

enum poll_rc
{
  POLL_ERROR = -1,
  POLL_TIMEOUT = 0,
};

enum recv_rc
{
  RECV_ERROR = -1,
  RECV_CLOSED = 0,
};

enum send_rc
{
  SEND_ERROR = -1,
};

/**
 * End of Network stuff
 */

/**
 * Start of make_unique for C++11
 */

#if __cplusplus == 201103L
#ifndef COMPAT_STD_MAKE_UNIQUE
#define COMPAT_STD_MAKE_UNIQUE
#include <memory>
namespace std
{
template<typename T, typename... Args>
std::unique_ptr<T>
make_unique(Args&&... args)
{
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
} /* namespace std */
#endif /* COMPAT_STD_MAKE_UNIQUE */
#endif /* __cplusplus == 201103L */

/**
 * End of make_unique for C++11
 */

/**
 * Start of Filesystem for C++11 and C++17
 */

#if defined(__has_include)
# if __cplusplus >= 201703L && __has_include(<filesystem>)
  /* For debug */
  /* #pragma message ( "Used C++17 <filesystem>" ) */
  #include <filesystem>
  namespace nsfs = std::filesystem;
# elif __cplusplus >= 201103L && __has_include(<boost/filesystem.hpp>)
  /* For debug */
  /* #pragma message ( "Used <boost/filesystem.hpp>" ) */
  #include <boost/filesystem.hpp>
  namespace nsfs = boost::filesystem;
# else
#    error Missing the <filesystem> header!
# endif
#else
#  error Missing the "__has_include" module!
#endif

/**
 * End of Filesystem for C++11 and C++17
 */

#endif /* BOTE_SRC_COMPATH_H*/
