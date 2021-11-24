/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef _VERSION_H__
#define _VERSION_H__

#define CODENAME "Purple Boat"

#define STRINGIZE(x) #x
#define MAKE_VERSION(a, b, c, d) STRINGIZE(a) "." STRINGIZE(b) "." STRINGIZE(c) "-" STRINGIZE(d)

#define PBOTE_VERSION_MAJOR 0
#define PBOTE_VERSION_MINOR 7
#define PBOTE_VERSION_MICRO 3
#define PBOTE_VERSION_PATCH 0
#define PBOTE_VERSION                                                          \
  MAKE_VERSION(PBOTE_VERSION_MAJOR, PBOTE_VERSION_MINOR, PBOTE_VERSION_MICRO, PBOTE_VERSION_PATCH)
#define VERSION PBOTE_VERSION

#endif // _VERSION_H__