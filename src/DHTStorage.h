/**
 * Copyright (C) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTE_SRC_DHTSTORAGE_H_
#define PBOTE_SRC_DHTSTORAGE_H_

#include <mutex>

#include "FileSystem.h"
#include "Packet.h"

namespace pbote
{
namespace kademlia
{

#define STORE_SUCCESS 0
#define STORE_FILE_EXIST (-1)
#define STORE_FILE_OPEN_ERROR (-2)
#define STORE_FILE_NOT_STORED (-3)

const int32_t store_duration = 8640000; /// 100 * 24 * 3600 (100 days)

template<class T>
T base_name(T const & path, T const & delims = "/\\") {
  return path.substr(path.find_last_of(delims) + 1);
}

template<class T>
T remove_extension(T const & filename) {
  typename T::size_type const p(filename.find_last_of('.'));
  return p > 0 && p != T::npos ? filename.substr(0, p) : filename;
}

class DHTStorage {
 public:
  DHTStorage() = default;
  //~DHTStorage();

  void update();
  int safe(const std::vector<uint8_t>& data);
  bool deleteIndex(i2p::data::Tag<32> key);
  bool deleteEmail(i2p::data::Tag<32> key);

  std::vector<uint8_t> getIndex(i2p::data::Tag<32> key);
  std::vector<uint8_t> getEmail(i2p::data::Tag<32> key);
  std::vector<uint8_t> getContact(i2p::data::Tag<32> key);

  std::vector<std::string> getIndexList() {return local_index_packets;}
  std::vector<std::string> getEmailList() {return local_email_packets;}
  std::vector<std::string> getContactList() {return local_contact_packets;}

  void set_storage_limit();
  bool limit_reached(size_t data_size);
  double limit_used() {return (double)((100 / (double)limit) * (double)used);}

 private:
  std::vector<uint8_t> getPacket(pbote::type type, i2p::data::Tag<32> key);
  bool exist(pbote::type type, i2p::data::Tag<32> key);
  static bool find(const std::vector<std::string>& list, i2p::data::Tag<32> key);

  int safeIndex(i2p::data::Tag<32> key, const std::vector<uint8_t>& data);
  int safeEmail(i2p::data::Tag<32> key, const std::vector<uint8_t>& data);
  int safeContact(i2p::data::Tag<32> key, const std::vector<uint8_t>& data);

  int update_index(i2p::data::Tag<32> key, const std::vector<uint8_t>& data);
  int clean_index(i2p::data::Tag<32> key, int32_t current_timestamp);

  void loadLocalIndexPackets();
  void loadLocalEmailPackets();
  void loadLocalContactPackets();

  size_t suffix_to_multiplier(const std::string &size_str);

  void update_storage_usage();

  void remove_old_packets();
  void remove_old_entries();

  size_t limit;
  size_t used;
  int update_counter;

  std::mutex index_mutex, email_mutex, contact_mutex;
  std::vector<std::string> local_index_packets;
  std::vector<std::string> local_email_packets;
  std::vector<std::string> local_contact_packets;
};

} // kademlia
} // pbote

#endif //PBOTE_SRC_DHTSTORAGE_H_
