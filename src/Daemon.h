/**
 * Copyright (c) 2019-2020 polistern
 */

#ifndef DAEMON_H__
#define DAEMON_H__

#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <thread>

namespace pbote {
namespace util {

class Daemon_Singleton_Private;
class Daemon_Singleton {
 public:
  virtual bool init(int argc, char *argv[], std::shared_ptr<std::ostream> logstream);
  virtual bool init(int argc, char *argv[]);
  virtual bool start();
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

#if defined(QT_GUI_LIB) // check if QT
#define Daemon i2p::util::DaemonQT::Instance()
// dummy, invoked from RunQT
class DaemonQT : public i2p::util::Daemon_Singleton {
public:
  static DaemonQT &Instance() {
    static DaemonQT instance;
    return instance;
  }
};

#elif defined(_WIN32)
#define Daemon i2p::util::DaemonWin32::Instance()
class DaemonWin32 : public Daemon_Singleton {
public:
  static DaemonWin32 &Instance() {
    static DaemonWin32 instance;
    return instance;
  }

  bool init(int argc, char *argv[]);
  bool start();
  bool stop();
  void run();

  bool isGraceful;

  DaemonWin32() : isGraceful(false) {}
};
#elif (defined(ANDROID) && !defined(ANDROID_BINARY))
#define Daemon i2p::util::DaemonAndroid::Instance()
// dummy, invoked from android/jni/DaemonAndroid.*
class DaemonAndroid : public i2p::util::Daemon_Singleton {
public:
  static DaemonAndroid &Instance() {
    static DaemonAndroid instance;
    return instance;
  }
};
#else
#define Daemon pbote::util::DaemonLinux::Instance()
class DaemonLinux : public Daemon_Singleton {
 public:
  static DaemonLinux &Instance() {
    static DaemonLinux instance;
    return instance;
  }
  // DaemonLinux();
  //~DaemonLinux();

  bool start();
  bool stop();
  void run();

 private:
  std::string pidfile;
  int pidFH;

 public:
  int gracefulShutdownInterval; // in seconds
};

#endif
} // namespace util
} // namespace pbote

#endif // DAEMON_H__
