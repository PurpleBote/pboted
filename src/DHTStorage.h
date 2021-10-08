/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef PBOTE_SRC_DHTSTORAGE_H_
#define PBOTE_SRC_DHTSTORAGE_H_

#include "FS.h"
#include "Packet.h"

namespace pbote {
namespace kademlia {

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
  bool safe(std::vector<uint8_t> data);
  bool deleteIndex(i2p::data::Tag<32> key);
  bool deleteEmail(i2p::data::Tag<32> key);

  std::vector<uint8_t> getIndex(i2p::data::Tag<32> key);
  std::vector<uint8_t> getEmail(i2p::data::Tag<32> key);
  std::vector<uint8_t> getContact(i2p::data::Tag<32> key);

  std::vector<std::string> getIndexList() {return local_index_packets;}
  std::vector<std::string> getEmailList() {return local_email_packets;}
  std::vector<std::string> getContactList() {return local_contact_packets;}

 private:
  std::vector<uint8_t> getPacket(pbote::type type, i2p::data::Tag<32> key);
  bool exist(pbote::type type, i2p::data::Tag<32> key);
  static bool find(const std::vector<std::string>& list, i2p::data::Tag<32> key);

  static bool safeIndex(i2p::data::Tag<32> key, std::vector<uint8_t> data);
  static bool safeEmail(i2p::data::Tag<32> key, std::vector<uint8_t> data);
  static bool safeContact(i2p::data::Tag<32> key, std::vector<uint8_t> data);

  void loadLocalIndexPackets();
  void loadLocalEmailPackets();
  void loadLocalContactPackets();

  // ToDo: remove files older than 100 * 24 * 3600 * 1000L ( 100 days)

  std::vector<std::string> local_index_packets;
  std::vector<std::string> local_email_packets;
  std::vector<std::string> local_contact_packets;
};

} // kademlia
} // pbote

#endif //PBOTE_SRC_DHTSTORAGE_H_
