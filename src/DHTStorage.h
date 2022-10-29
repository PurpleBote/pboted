/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#pragma once
#ifndef PBOTED_SRC_DHTSTORAGE_H
#define PBOTED_SRC_DHTSTORAGE_H

#include <mutex>

#include "FileSystem.h"
#include "Packet.h"

namespace pbote
{
namespace kademlia
{

// 10 MiB
#define DHT_MIN_FREE_SPACE 10485760

#define STORE_SUCCESS 0
#define STORE_FILE_EXIST (-1)
#define STORE_FILE_OPEN_ERROR (-2)
#define STORE_FILE_NOT_STORED (-3)

/// How long the packet is kept in DHT storage
const int32_t store_duration = 8640000; /// 100 * 24 * 3600 (100 days)

template<class T>
T base_name (T const & path, T const & delims = "/\\")
{
  return path.substr (path.find_last_of (delims) + 1);
}

template<class T>
T remove_extension (T const & filename)
{
  typename T::size_type const p(filename.find_last_of ('.'));
  return p > 0 && p != T::npos ? filename.substr (0, p) : filename;
}

class DHTStorage
{
 public:
  DHTStorage () = default;
  //~DHTStorage ();

  void update ();
  int safe (const std::vector<uint8_t>& data);
  int safe_deleted (pbote::type type, const i2p::data::Tag<32>& key,
                    const std::vector<uint8_t>& data);
  bool Delete (pbote::type type, const i2p::data::Tag<32>& key,
               const char *ext = DEFAULT_FILE_EXTENSION);
  bool remove_index (const i2p::data::Tag<32>& index_dht_key,
                     const i2p::data::Tag<32>& email_dht_key,
                     const i2p::data::Tag<32>& del_auth);
  size_t remove_indices (const i2p::data::Tag<32>& index_dht_key,
                         const IndexDeleteRequestPacket& packet);

  std::vector<uint8_t> getIndex (i2p::data::Tag<32> key);
  std::vector<uint8_t> getEmail (i2p::data::Tag<32> key);
  std::vector<uint8_t> getContact (i2p::data::Tag<32> key);

  std::vector<uint8_t> getPacket (pbote::type type, i2p::data::Tag<32> key,
                                  const char *ext = DEFAULT_FILE_EXTENSION);

  std::set<std::string> getIndexList () {return local_index_packets;}
  std::set<std::string> getEmailList () {return local_email_packets;}
  std::set<std::string> getContactList () {return local_contact_packets;}

  void set_storage_limit ();
  bool limit_reached (size_t data_size);
  double limit_used () {return (double)((100 / (double)limit) * (double)used);}

 private:
  bool exist (pbote::type type, i2p::data::Tag<32> key);

  int safeIndex (i2p::data::Tag<32> key, const std::vector<uint8_t>& data);
  int safeEmail (i2p::data::Tag<32> key, const std::vector<uint8_t>& data);
  int safeContact (i2p::data::Tag<32> key, const std::vector<uint8_t>& data);

  int update_index (i2p::data::Tag<32> key, const std::vector<uint8_t>& data);
  int clean_index (i2p::data::Tag<32> key, int32_t current_timestamp);

  int safe_deleted_index (i2p::data::Tag<32> key,
                          const std::vector<uint8_t>& data);
  int safe_deleted_email (i2p::data::Tag<32> key,
                          const std::vector<uint8_t>& data);

  int update_deletion_info (pbote::type type, i2p::data::Tag<32> key,
                            const std::vector<uint8_t>& data);
  int clean_deletion_info (pbote::type type, i2p::data::Tag<32> key,
                           int32_t current_timestamp);

  void loadLocalIndexPackets ();
  void loadLocalEmailPackets ();
  void loadLocalContactPackets ();

  size_t suffix_to_multiplier (const std::string &size_str);

  void update_storage_usage ();

  void remove_old_packets ();
  void remove_old_entries ();

  size_t limit, used;
  int update_counter;

  std::recursive_mutex index_mutex, email_mutex, contact_mutex;
  std::set<std::string> local_index_packets;
  std::set<std::string> local_email_packets;
  std::set<std::string> local_contact_packets;
};

} // kademlia
} // pbote

#endif //PBOTE_SRC_DHTSTORAGE_H_
