/**
 * Copyright (c) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <cstdlib>

#include "BoteDaemon.h"

int
main (int argc, char *argv[])
{
  if (Daemon.init (argc, argv))
    {
      int res = Daemon.start ();
      if (res == 0)
        {
          Daemon.run ();
        }
      else if (res > 0)
        {
          return EXIT_SUCCESS;
        }
      else
        {
          return EXIT_FAILURE;
        }
      Daemon.stop ();
    }
  return EXIT_SUCCESS;
}
