/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <cstdlib>

#include "BoteDaemon.h"

#ifndef _WIN32
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

#else // _WIN32
INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, PSTR, INT)
{
  Daemon.m_hInstance = hInstance;

  if (Daemon.init (__argc, __argv))
  {
    if (Daemon.start () == EXIT_SUCCESS)
    {
      Daemon.run ();
    }
    else
    {
      return EXIT_FAILURE;
    }
    Daemon.stop ();
  }
  return EXIT_SUCCESS;
}
#endif
