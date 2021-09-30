/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef PBOTE_SRC_DHTSTORAGE_H_
#define PBOTE_SRC_DHTSTORAGE_H_

#include "FS.h"
#include "Packet.h"

namespace pbote {
namespace kademlia {

class DHTStorage {
 public:
  DHTStorage() = default;
  //~DHTStorage();

  void update();
  void safe(uint8_t* key, std::vector<uint8_t> data);
  bool deleteIndex(uint8_t* key);
  bool deleteEmail(uint8_t* key);

  std::vector<uint8_t> getIndex(uint8_t* key);
  std::vector<uint8_t> getEmail(uint8_t* key);
  std::vector<uint8_t> getContact(uint8_t* key);

  std::vector<std::string> getIndexList() {return local_index_packets;}
  std::vector<std::string> getEmailList() {return local_email_packets;}
  std::vector<std::string> getContactList() {return local_contact_packets;}

 private:
  static std::vector<uint8_t> getPacket(pbote::type type, uint8_t* key);
  bool exist(pbote::type type, uint8_t* key);
  static bool find(const std::vector<std::string>& list, uint8_t* key);

  void safeIndex(uint8_t* key, std::vector<uint8_t> data);
  void safeEmail(uint8_t* key, std::vector<uint8_t> data);
  void safeContact(uint8_t* key, std::vector<uint8_t> data);

  void loadLocalIndexPackets();
  void loadLocalEmailPackets();
  void loadLocalContactPackets();

  std::vector<std::string> local_index_packets;
  std::vector<std::string> local_email_packets;
  std::vector<std::string> local_contact_packets;
};

}
}

#endif //PBOTE_SRC_DHTSTORAGE_H_
