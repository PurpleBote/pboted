/**
 * Copyright (c) 2013-2016, The PurpleI2P Project
 * Copyright (c) 2019-2021 polistern
 *
 * This file is part of Purple i2pd project and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <algorithm>
#include <boost/filesystem.hpp>

#ifdef _WIN32
#include <shlobj.h>
#include <windows.h>
#endif

#include "FileSystem.h"
#include "Logging.h"

namespace pbote {
namespace fs {

std::string appName = "pboted";
std::string dataDir = "";
std::string dirSep = "/";
const std::vector<std::string> dir_list = {"DHTindex", "DHTemail", "DHTdirectory", "inbox", "incomplete", "outbox", "sent"};

const std::string &GetAppName() { return appName; }

void SetAppName(const std::string &name) { appName = name; }

const std::string &GetDataDir() { return dataDir; }

void DetectDataDir(const std::string &cmdline_param, bool isService) {
  if (!cmdline_param.empty()) {
    dataDir = cmdline_param;
    return;
  }
  // otherwise use /data/files
  char *home = getenv("HOME");
  if (isService) {
    dataDir = "/var/lib/" + appName;
  } else if (home != nullptr && strlen(home) > 0) {
    dataDir = std::string(home) + "/." + appName;
  } else {
    dataDir = "/tmp/" + appName;
  }
}

bool Init() {
  if (!boost::filesystem::exists(dataDir))
    boost::filesystem::create_directory(dataDir);

  for (const auto& dir_name : dir_list) {
    std::string dir_path = DataDirPath(dir_name);
    if (!boost::filesystem::exists(dir_path))
      boost::filesystem::create_directory(dir_path);
  }

  return true;
}

bool ReadDir(const std::string &path, std::vector<std::string> &files) {
  if (!boost::filesystem::exists(path))
    return false;
  boost::filesystem::directory_iterator it(path);
  boost::filesystem::directory_iterator end;

  for (; it != end; it++) {
    if (!boost::filesystem::is_regular_file(it->status()))
      continue;
    files.push_back(it->path().string());
  }

  return true;
}

bool Exists(const std::string &path) { return boost::filesystem::exists(path); }

uint32_t GetLastUpdateTime(const std::string &path) {
  if (!boost::filesystem::exists(path))
    return 0;
  boost::system::error_code ec;
  auto t = boost::filesystem::last_write_time(path, ec);
  return ec ? 0 : t;
}

bool Remove(const std::string &path) {
  if (!boost::filesystem::exists(path))
    return false;
  return boost::filesystem::remove(path);
}

bool CreateDirectory(const std::string &path) {
  if (boost::filesystem::exists(path) &&
      boost::filesystem::is_directory(boost::filesystem::status(path)))
    return true;
  return boost::filesystem::create_directory(path);
}

void HashedStorage::SetPlace(const std::string &path) {
  root = path + pbote::fs::dirSep + name;
}

bool HashedStorage::Init(const char *chars, size_t count) {
  if (!boost::filesystem::exists(root)) {
    boost::filesystem::create_directories(root);
  }

  for (size_t i = 0; i < count; i++) {
    auto p = root + pbote::fs::dirSep + prefix1 + chars[i];
    if (boost::filesystem::exists(p))
      continue;
    if (boost::filesystem::create_directory(p))
      continue; /* ^ throws exception on failure */
    return false;
  }
  return true;
}

std::string HashedStorage::Path(const std::string &ident) const {
  std::string safe_ident = ident;
  std::replace(safe_ident.begin(), safe_ident.end(), '/', '-');
  std::replace(safe_ident.begin(), safe_ident.end(), '\\', '-');

  std::stringstream t("");
  t << this->root << pbote::fs::dirSep;
  t << prefix1 << safe_ident[0] << pbote::fs::dirSep;
  t << prefix2 << safe_ident << "." << suffix;

  return t.str();
}

void HashedStorage::Remove(const std::string &ident) {
  std::string path = Path(ident);
  if (!boost::filesystem::exists(path))
    return;
  boost::filesystem::remove(path);
}

void HashedStorage::Traverse(std::vector<std::string> &files) {
  Iterate([&files](const std::string &fname) { files.push_back(fname); });
}

void HashedStorage::Iterate(FilenameVisitor v) {
  boost::filesystem::path p(root);
  boost::filesystem::recursive_directory_iterator it(p);
  boost::filesystem::recursive_directory_iterator end;

  for (; it != end; it++) {
    if (!boost::filesystem::exists(it->path()))
      continue;
    if (!boost::filesystem::is_regular_file(it->status()))
      continue;
    const std::string &t = it->path().string();
    v(t);
  }
}
} // namespace fs
} // namespace pbote
