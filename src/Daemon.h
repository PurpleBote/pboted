/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef PBOTE_SRC_DAEMON_H__
#define PBOTE_SRC_DAEMON_H__

//#include <iostream>
#include <memory>
#include <ostream>
#include <string>
//#include <thread>

namespace pbote {
namespace util {

class Daemon_Singleton_Private;
class Daemon_Singleton {
 public:
  virtual bool init(int argc, char *argv[], std::shared_ptr<std::ostream> logstream);
  virtual bool init(int argc, char *argv[]);
  virtual int start();
  virtual bool stop();
  virtual void run() {};

  bool isDaemon;
  bool running;

 protected:
  Daemon_Singleton();
  virtual ~Daemon_Singleton();

  bool IsService() const;

  // d-pointer for httpServer, httpProxy, etc.
  class Daemon_Singleton_Private;
  Daemon_Singleton_Private &d;
};

#define Daemon pbote::util::DaemonLinux::Instance()
class DaemonLinux : public Daemon_Singleton {
 public:
  static DaemonLinux &Instance() {
    static DaemonLinux instance;
    return instance;
  }
  // DaemonLinux();
  //~DaemonLinux();

  int start() override;
  bool stop() override;
  void run() override;

 private:
  std::string pidfile;
  int pidFH;

 public:
  int gracefulShutdownInterval; // in seconds
};

//#endif
} // namespace util
} // namespace pbote

#endif // PBOTE_SRC_DAEMON_H__
