/**
 * Copyright (C) 2019-2022, polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTED_SRC_BOTEDAEMON_H__
#define PBOTED_SRC_BOTEDAEMON_H__

#include <memory>
#include <ostream>
#include <string>

namespace pbote
{
namespace util
{

class Daemon_Singleton_Private;

class Daemon_Singleton
{
public:
  virtual bool init(int argc, char *argv[],
                    std::shared_ptr<std::ostream> logstream);
  virtual bool init(int argc, char *argv[]);
  virtual int start();
  virtual bool stop();
  virtual void run(){};

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
class DaemonLinux : public Daemon_Singleton
{
public:
  static DaemonLinux &Instance()
    {
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

} // namespace util
} // namespace pbote

#endif // PBOTE_SRC_DAEMON_H__
