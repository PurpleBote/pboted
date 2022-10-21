/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef BOTE_VERSION_H
#define BOTE_VERSION_H

#define CODENAME "Plus Bote Daemon"

#define STRINGIZE(x) #x
#define MAKE_VERSION(a, b, c) STRINGIZE (a) "." STRINGIZE (b) "." STRINGIZE (c)
#define MAKE_PROTO_VERSION(a, b) STRINGIZE (a) "." STRINGIZE (b)

#define PBOTED_VERSION_MAJOR 0
#define PBOTED_VERSION_MINOR 7
#define PBOTED_VERSION_MICRO 11

#define PBOTED_VERSION                                                        \
  MAKE_VERSION (PBOTED_VERSION_MAJOR, PBOTED_VERSION_MINOR, PBOTED_VERSION_MICRO)

#define BOTE_VERSION_MAJOR 4
#define BOTE_VERSION_MINOR 1

#define BOTE_VERSION                                                          \
  MAKE_PROTO_VERSION (BOTE_VERSION_MAJOR, BOTE_VERSION_MINOR)

#define VERSION PBOTED_VERSION " " "(" BOTE_VERSION ")"

#endif // BOTE_VERSION_H
