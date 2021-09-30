/**
 * Copyright (c) 2019-2020 polistern
 */

#include <cstdlib>

#include "Daemon.h"

int main(int argc, char *argv[]) {
  if (Daemon.init(argc, argv)) {
    bool res = Daemon.start();
    if (res) {
      Daemon.run();
    } else {
      return EXIT_FAILURE;
    }
    Daemon.stop();
  }
  return EXIT_SUCCESS;
}
