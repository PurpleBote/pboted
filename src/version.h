/**
 * Copyright (c) 2019-2022 polistern
 */

#ifndef BOTE_VERSION_H_
#define BOTE_VERSION_H_

#define CODENAME "Plus Bote Daemon"

#define STRINGIZE(x) #x
#define MAKE_VERSION(a, b, c) STRINGIZE (a) "." STRINGIZE (b) "." STRINGIZE (c)

#define PBOTE_VERSION_MAJOR 0
#define PBOTE_VERSION_MINOR 7
#define PBOTE_VERSION_MICRO 6

#define PBOTE_VERSION                                                         \
  MAKE_VERSION (PBOTE_VERSION_MAJOR, PBOTE_VERSION_MINOR, PBOTE_VERSION_MICRO)
#define VERSION PBOTE_VERSION

#endif // BOTE_VERSION_H_
