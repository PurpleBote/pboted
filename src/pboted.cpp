/**
 * Copyright (c) 2019-2021 polistern
 */

#include <cstdlib>

#include "BoteDaemon.h"

int main(int argc, char *argv[]) {
  if (Daemon.init(argc, argv)) {
    int res = Daemon.start();
    if (res == 0) {
      Daemon.run();
    } else if (res > 0) {
      return EXIT_SUCCESS;
    } else {
      return EXIT_FAILURE;
    }
    Daemon.stop();
  }
  return EXIT_SUCCESS;
}
