/**
 * Copyright (c) 2019-2021 polistern
 */

#include <openssl/sha.h>
#include <iterator>
#include <utility>
#include <vector>
#include <ctime>

#include "BoteContext.h"
#include "DHTworker.h"
#include "EmailWorker.h"

namespace pbote {
namespace kademlia {

EmailWorker email_worker;

EmailWorker::EmailWorker()
    : started_(false),
      m_check_email_thread_(nullptr),
      m_send_email_thread_(nullptr),
      m_worker_thread_(nullptr) {}

EmailWorker::~EmailWorker() {
  stop();
}

void EmailWorker::start() {
  if (!started_) {
    started_ = true;
    email_identities = context.getEmailIdentities();
    if (email_identities.empty()) {
      LogPrint(eLogError, "EmailWorker: have no identities for start");
    } else {
      LogPrint(eLogInfo, "EmailWorker: have ", email_identities.size(), " identities");
      startCheckEmailTask();
      startSendEmailTask();
    }
    m_worker_thread_ = new std::thread(std::bind(&EmailWorker::run, this));
  }
}

void EmailWorker::stop() {
  LogPrint(eLogWarning, "EmailWorker: stopping");
  if (started_) {
    started_ = false;
    stopCheckEmailTask();
    stopSendEmailTask();

    if (m_worker_thread_) {
      m_worker_thread_->join();
      delete m_worker_thread_;
      m_worker_thread_ = nullptr;
    }
  }
  LogPrint(eLogWarning, "EmailWorker: stopped");
}

void EmailWorker::startCheckEmailTask() {
  if (started_) {
    LogPrint(eLogInfo, "EmailWorker: start checkEmailTask");
    m_check_email_thread_ = new std::thread(std::bind(&EmailWorker::checkEmailTask, this));
  }
}

bool EmailWorker::stopCheckEmailTask() {
  LogPrint(eLogInfo, "EmailWorker: stop checkEmailTask");

  if (m_check_email_thread_ && !started_) {
    m_check_email_thread_->join();
    delete m_check_email_thread_;
    m_check_email_thread_ = nullptr;
  }
  LogPrint(eLogInfo, "EmailWorker: checkEmailTask stopped");
  return true;
}

void EmailWorker::startSendEmailTask() {
  if (started_) {
    LogPrint(eLogInfo, "EmailWorker: start sendEmailTask");
    m_send_email_thread_ = new std::thread(std::bind(&EmailWorker::sendEmailTask, this));
  }
}

bool EmailWorker::stopSendEmailTask() {
  LogPrint(eLogInfo, "EmailWorker: stop sendEmailTask");

  if (m_send_email_thread_ && !started_) {
    m_send_email_thread_->join();
    delete m_send_email_thread_;
    m_send_email_thread_ = nullptr;
  }
  LogPrint(eLogInfo, "EmailWorker: sendEmailTask stopped");
  return true;
}

pbote::IndexPacket EmailWorker::parseIndexPkt(uint8_t *buf, size_t len, bool from_net) {
  /// 38 cause type[1] + ver[1] + DH[32] + nump[4]
  if (len < 38) {
    LogPrint(eLogWarning, "EmailWorker: parseIndexPkt: payload is too short");
    return {};
  }
  IndexPacket packet;
  uint16_t offset = 0;

  std::memcpy(&packet.type, buf, 1);
  offset += 1;
  std::memcpy(&packet.ver, buf + offset, 1);
  offset += 1;
  std::memcpy(&packet.hash, buf + offset, 32);
  offset += 32;
  std::memcpy(&packet.nump, buf + offset, 4);
  offset += 4;
  if (from_net)
    packet.nump = ntohl(packet.nump);

  LogPrint(eLogDebug, "EmailWorker: parseIndexPkt: nump: ", packet.nump);

  if (!(packet.type == (uint8_t) 'I')) {
    LogPrint(eLogWarning, "EmailWorker: parseIndexPkt: wrong packet type: ", packet.type);
    return {};
  }

  if (!(packet.ver == (uint8_t) 4)) {
    LogPrint(eLogWarning, "EmailWorker: parseIndexPkt: wrong packet version: ", (unsigned) packet.ver);
    return {};
  }

  // Check if payload length enough to parse all entries
  if (len < (38 + (68 * packet.nump))) {
    LogPrint(eLogWarning, "EmailWorker: parseIndexPkt: incomplete packet!");
    return {};
  }

  for (uint32_t i = 0; i < packet.nump; i--) {
    pbote::IndexPacket::Entry entry;
    std::memcpy(&entry.key, buf + offset, 32);
    offset += 32;
    i2p::data::Tag<32> key(entry.key);
    LogPrint(eLogDebug, "EmailWorker: parseIndexPkt: mail key: ", key.ToBase64());

    std::memcpy(&entry.dv, buf + offset, 32);
    offset += 32;
    i2p::data::Tag<32> dv(entry.dv);
    LogPrint(eLogDebug, "EmailWorker: parseIndexPkt: mail dvr: ", dv.ToBase64());

    std::memcpy(&entry.time, buf + offset, 4);
    offset += 4;
    packet.data.push_back(entry);
  }
  return packet;
}

pbote::EmailEncryptedPacket EmailWorker::parseEmailEncryptedPkt(uint8_t *buf, size_t len, bool from_net) {
  LogPrint(eLogDebug, "EmailWorker: parseEmailEncryptedPkt: payload size: ", len);
  /// 105 cause type[1] + ver[1] + key[32] + stored_time[4] + delete_hash[32] + alg[1] + length[2] + DA[32]
  if (len < 105) {
    LogPrint(eLogWarning, "EmailWorker: parseEmailEncryptedPkt: payload is too short");
    return {};
  }

  size_t offset = 0;
  EmailEncryptedPacket packet;

  std::memcpy(&packet.type, buf, 1);
  offset += 1;
  std::memcpy(&packet.ver, buf + offset, 1);
  offset += 1;

  if (!(packet.type == (uint8_t) 'E')) {
    LogPrint(eLogWarning, "EmailWorker: parseEmailEncryptedPkt: wrong packet type: ", packet.type);
    return {};
  }

  if (!(packet.ver == (uint8_t) 4)) {
    LogPrint(eLogWarning, "EmailWorker: parseEmailEncryptedPkt: wrong packet version: ", unsigned(packet.ver));
    return {};
  }

  std::memcpy(&packet.key, buf + offset, 32);
  offset += 32;
  std::memcpy(&packet.stored_time, buf + offset, 4);
  LogPrint(eLogDebug, "EmailWorker: parseEmailEncryptedPkt: packet.stored_time: ", packet.stored_time);
  offset += 4;
  std::memcpy(&packet.delete_hash, buf + offset, 32);
  offset += 32;
  std::memcpy(&packet.alg, buf + offset, 1);
  LogPrint(eLogDebug, "EmailWorker: parseEmailEncryptedPkt: packet.alg: ", unsigned(packet.alg));
  offset += 1;

  std::vector<uint8_t> data_for_verify(buf + offset, buf + len);

  std::memcpy(&packet.length, buf + offset, 2);
  LogPrint(eLogDebug, "EmailWorker: parseEmailEncryptedPkt: packet.length: ", packet.length);
  offset += 2; // DATA length

  i2p::data::Tag<32> ver_hash(packet.key);
  uint8_t data_hash[32];
  SHA256(data_for_verify.data(), data_for_verify.size(), data_hash);
  i2p::data::Tag<32> cur_hash(data_hash);

  LogPrint(eLogDebug, "EmailWorker: parseEmailEncryptedPkt: ver_hash: ", ver_hash.ToBase64());
  LogPrint(eLogDebug, "EmailWorker: parseEmailEncryptedPkt: cur_hash: ", cur_hash.ToBase64());

  if (ver_hash != cur_hash) {
    LogPrint(eLogError, "EmailWorker: parseEmailEncryptedPkt: hash mismatch");
    return {};
  }

  if (from_net) {
    packet.stored_time = ntohl(packet.stored_time);
    packet.length = ntohs(packet.length);
  }
  LogPrint(eLogDebug, "EmailWorker: parseEmailEncryptedPkt: alg: ", unsigned(packet.alg), ", length: ", packet.length);
  std::vector<uint8_t> data(buf + offset, buf + offset + packet.length);
  packet.edata = data;
  return packet;
}

std::vector<uint8_t> EmailWorker::decryptData(uint8_t *enc, size_t elen) {
  // ToDo: pass identity to function
  for (const auto &identity : email_identities) {
    std::vector<uint8_t> data = identity->identity.Decrypt(enc, elen);
    return data;
  }
  return {};
}

std::vector<uint8_t> EmailWorker::encryptData(uint8_t* data, size_t dlen, const pbote::EmailIdentityPublic& recipient) {
  // ToDo: pass identity to function as parameter
  for (const auto &identity : email_identities) {
    std::vector<uint8_t> enc_data = identity->identity.Encrypt(data, dlen, recipient.GetEncryptionPublicKey());
    return enc_data;
  }
  return {};
}

void EmailWorker::run() {
  while (started_) {
    auto new_identities = context.getEmailIdentities();
    if (!new_identities.empty()) {
      email_identities = new_identities;
      LogPrint(eLogInfo, "EmailWorker: update identities, now: ", email_identities.size());
    } else {
      LogPrint(eLogWarning, "EmailWorker: have no identities for start");
    }

    if (!m_check_email_thread_ && started_ && !new_identities.empty()) {
      LogPrint(eLogDebug, "EmailWorker: checkEmailTask not run, try to start");
      startCheckEmailTask();
    }

    if (!m_send_email_thread_ && started_ && !new_identities.empty()) {
      LogPrint(eLogDebug, "EmailWorker: sendEmailTask not run, try to start");
      startSendEmailTask();
    }

    std::this_thread::sleep_for(std::chrono::seconds(60));
  }
}

// ToDo: call for any identity individual in separated threads
// ToDo: check packets locally with different task?
void EmailWorker::checkEmailTask() {
  while (started_) {
    for (const auto &email_identity : email_identities) {
      auto index_packets = retrieveIndex(email_identity);

      //auto index_packets = loadLocalIndex();
      auto local_index_packet = DHT_worker.getIndex(email_identity->identity.GetPublic()->GetIdentHash());
      if (!local_index_packet.empty()) {
        LogPrint(eLogDebug, "EmailWorker: checkEmailTask: got local index packet for identity: ",
                 email_identity->publicName);
        /// from_net is true, because we save it as is
        auto parsed_local_index_packet = parseIndexPkt(local_index_packet.data(), local_index_packet.size(), true);
        if (parsed_local_index_packet.data.size() == parsed_local_index_packet.nump) {
          index_packets.push_back(parsed_local_index_packet);
        }
      }
      LogPrint(eLogDebug, "EmailWorker: checkEmailTask: index count: ", index_packets.size());

      auto enc_mail_packets = retrieveEmailEncryptedPacket(index_packets);
      LogPrint(eLogDebug, "EmailWorker: checkEmailTask: mail count: ", enc_mail_packets.size());

      auto emails = processEmail(enc_mail_packets);

      // ToDo: move to independent task
      for (const auto& mail : emails)
        saveEmailInboxPacket(mail);

      // wait until all EmailPacketTasks are done
      // ToDo: need interrupt handler

      // delete index packets if all EmailPacketTasks finished without throwing an exception
      // ToDo: generate and sent delete requests for founded index packets after save

      // ToDo: generate and sent delete requests for founded mail packets after save

      // check sent stored Encrypted packets status
      //   if nodes sent empty response - mark as deleted (delivered)
    }
    LogPrint(eLogInfo, "EmailWorker: checkEmailTask: Round complete");
    std::this_thread::sleep_for(std::chrono::seconds(60));
  }
}

void EmailWorker::incompleteEmailTask() {
  // ToDo: just for tests, need to implement
  // ToDo: for multipart mail packets
  /*uint8_t compress_alg;
  memcpy(&compress_alg, buf + offset, 1);
  offset += 1;

  uint32_t output_sz;
  LogPrint(eLogDebug, "Email: parseEmailUnencryptedPkt: compress alg: ", (unsigned) compress_alg);
  if ((unsigned) compress_alg == (uint8_t) 1) {
    LogPrint(eLogDebug, "Email: parseEmailUnencryptedPkt: data compressed, start decompress");
    std::vector<uint8_t> output;
    UncompressInc(output, std::vector<uint8_t>(buf + offset, buf + len));
    auto decomp = lzmaDecompress(buf + offset, len - offset, &output_sz);
    if (!decomp) {
      LogPrint(eLogWarning, "Email: parseEmailUnencryptedPkt: decompressing error");
      return pbote::EmailUnencryptedPacket();
    }
    packet.data = std::vector<uint8_t>(decomp, decomp + output_sz);
  } else {
    LogPrint(eLogDebug, "Email: parseEmailUnencryptedPkt: data uncompressed, save as is");
  }
  LogPrint(eLogDebug, "Email: parseEmailUnencryptedPkt: data: ", packet.data.data());*/
}

void EmailWorker::sendEmailTask() {
  while (started_) {
    // compress packet with LZMA
    // ToDo: don't forget, for tests sent uncompressed
    //for (auto packet : emailPackets)
    //  lzmaCompress(packet.data, packet.data);
    // ToDo: slice big packet

    std::vector<std::string> nodes;

    auto outbox = checkOutbox();
    // check if we have mail in outbox
    if (!outbox.empty()) {
      // create Encrypted Email Packet
      for (const auto &email: outbox) {
        // ToDo: move to function
        pbote::EmailEncryptedPacket enc_packet;
        auto packet = email->getDecrypted();

        // Get hash of Delete Auth
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Get hash of Delete Auth");
        SHA256(packet.DA, 32, enc_packet.delete_hash);
        i2p::data::Tag<32> del_hash(enc_packet.delete_hash);
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: del_hash: ", del_hash.ToBase64());

        // Create recipient
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Create recipient");
        pbote::EmailIdentityPublic recipient_identity;
        std::string to_address = email->getToAddresses();
        to_address.erase(std::remove_if(to_address.begin(),
                                        to_address.end(),
                                        [](uint8_t x) { return std::isspace(x); }),
                         to_address.end());

        std::string cryptoPubKey = "A" + to_address.substr(0, 43);
        std::string signingPubKey = "A" + to_address.substr(43, 43);

        to_address = cryptoPubKey + signingPubKey;

        if (recipient_identity.FromBase64(to_address) == 0) {
          LogPrint(eLogWarning, "EmailWorker: sendEmailTask: Can't create identity from \"TO\" header, skip mail");
          email->setSkiped();
          continue;
        }

        LogPrint(eLogDebug,
                 "EmailWorker: sendEmailTask: Recipient hash: ",
                 recipient_identity.GetIdentHash().ToBase64());

        // Encrypt data
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Encrypt data");
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: packet.data.size: ", packet.data.size());
        auto packet_bytes = packet.toByte();
        enc_packet.edata = encryptData(packet_bytes.data(), packet_bytes.size(), recipient_identity);
        enc_packet.length = enc_packet.edata.size();
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: enc_packet.edata.size(): ", enc_packet.edata.size());
        // ToDo: for now only suppoted ECDH-256 / ECDSA-256
        enc_packet.alg = 2;
        enc_packet.stored_time = 0;

        // Get hash of data + length for DHT key
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Get hash of data + length for DHT key");
        uint8_t data_for_hash[2 + enc_packet.edata.size()];
        uint8_t v_length[2] = { static_cast<uint8_t>(enc_packet.length & 0xff),
                                static_cast<uint8_t>(enc_packet.length >> 8)};
        memcpy(data_for_hash, &v_length, 2);
        memcpy(data_for_hash + 2, enc_packet.edata.data(), enc_packet.edata.size());
        SHA256(data_for_hash, 2 + enc_packet.edata.size(), enc_packet.key);
        i2p::data::Tag<32> dht_key(enc_packet.key);
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: dht_key : ", dht_key.ToBase64());
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: enc_packet.length : ", enc_packet.length);


        uint32_t test_time;
        uint8_t v_time[4] = { static_cast<uint8_t>(enc_packet.stored_time >> 24), static_cast<uint8_t>(enc_packet.stored_time >> 16),
                              static_cast<uint8_t>(enc_packet.stored_time >>  8), static_cast<uint8_t>(enc_packet.stored_time & 0xffff) };
        std::memcpy(&test_time, v_time, 4);

        uint16_t test_len;
        memcpy(&test_len, &v_length, 2);

        email->setEncrypted(enc_packet);
        //saveEmailEncryptedPacket(enc_packet);
      }

      // store Encrypted Email Packet
      for (const auto& email : outbox) {
        // ToDo: move to function
        if (email->skip()) {
          continue;
        }

        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Create Store Request packet");
        pbote::StoreRequestPacket store_packet;

        // For now it's not checking from Java-Bote side
        // ToDo: need to discuss
        //std::string temp_s("1:20:1303030600:admin@example.com::McMybZIhxKXu57jd:FOvXX");
        //store_packet.hashcash = std::vector<uint8_t>(temp_s.begin(), temp_s.end());
        store_packet.hashcash = email->getHashCash();
        store_packet.hc_length = store_packet.hashcash.size();
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: store_packet.hc_length: ", store_packet.hc_length);

        store_packet.length = email->getEncrypted().toByte().size();
        store_packet.data = email->getEncrypted().toByte();
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: store_packet.length: ", store_packet.length);

        // send Store Request with Encrypted Email Packet to nodes
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Send Store Request with Encrypted Email Packet to nodes");
        nodes = DHT_worker.store(i2p::data::Tag<32>(email->getEncrypted().key), email->getEncrypted().type, store_packet);
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Email send to ", nodes.size(), " nodes");
      }

      // Create and store Index Packet
      for (const auto& email : outbox) {
        // ToDo: move to function
        if (email->skip()) {
          continue;
        }

        pbote::IndexPacket new_index_packet;

        pbote::EmailIdentityPublic recipient_identity;
        std::string to_address = email->getToAddresses();
        to_address.erase(std::remove_if(to_address.begin(),
                                        to_address.end(),
                                        [](uint8_t x){return std::isspace(x);}),
                         to_address.end());
        //LogPrint(eLogDebug, "EmailWorker: sendEmailTask: to_address.size(): ", to_address.size());

        std::string cryptoPubKey = "A" + to_address.substr(0, 43);
        std::string signingPubKey = "A" + to_address.substr(43, 43);

        to_address = cryptoPubKey + signingPubKey;

        if (recipient_identity.FromBase64(to_address) == 0) {
          LogPrint(eLogWarning, "EmailWorker: sendEmailTask: Can't create identity from \"TO\" header, skip mail");
          email->setSkiped();
          continue;
        }

        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Recipient hash: ", recipient_identity.GetIdentHash().ToBase64());

        memcpy(new_index_packet.hash, recipient_identity.GetIdentHash().data(), 32);

        // ToDo: for test, need to rewrite
        new_index_packet.nump = 1;
        //for (const auto &email : encryptedEmailPackets) {
        pbote::IndexPacket::Entry entry{};
        memcpy(entry.key, email->getEncrypted().key, 32);
        memcpy(entry.dv, email->getEncrypted().delete_hash, 32);

        auto unix_timestamp = std::chrono::seconds(std::time(nullptr));
        auto value = std::chrono::duration_cast<std::chrono::seconds>(unix_timestamp);
        entry.time = value.count();

        new_index_packet.data.push_back(entry);
        //}

        pbote::StoreRequestPacket store_index_packet;
        // For now it's not checking from Java-Bote side
        // ToDo: need to discuss
        //std::string temp_s("1:20:1303030600:admin@example.com::McMybZIhxKXu57jd:FOvXX");
        //store_index_packet.hashcash = std::vector<uint8_t>(temp_s.begin(), temp_s.end());
        store_index_packet.hashcash = email->getHashCash();
        store_index_packet.hc_length = store_index_packet.hashcash.size();
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: store_index_packet.hc_length: ", store_index_packet.hc_length);

        auto index_packet = new_index_packet.toByte();

        store_index_packet.length = index_packet.size();
        store_index_packet.data = index_packet;

        // send Store Request with Index Packet to nodes
        nodes = DHT_worker.store(recipient_identity.GetIdentHash(), new_index_packet.type, store_index_packet);
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Index send to ", nodes.size(), " nodes");
      }
    }

    // ToDo: move mail to sent

    //   sent - compressed email packet with metadata:
    //     DHT key
    //     del ver hash
    //     deleted (delivered) flag if we can't find keys

    LogPrint(eLogInfo, "EmailWorker: sendEmailTask: Round complete");
    std::this_thread::sleep_for(std::chrono::seconds(60));
  }
}

std::vector<pbote::IndexPacket> EmailWorker::retrieveIndex(const std::shared_ptr<pbote::EmailIdentityFull> &identity) {
  auto ident_hash = identity->identity.GetPublic()->GetIdentHash().ToBase64();
  LogPrint(eLogDebug, "EmailWorker: retrieveIndex: Try to find index for: ", ident_hash);
  // Use findAll rather than findOne because some peers might have an incomplete set of
  // Email Packet keys, and because we want to send IndexPacketDeleteRequests to all of them.

  // ToDo: Look in DHT storage if we have some for us; if no - just wait for timeout

  auto results = DHT_worker.findAll(identity->identity.GetPublic()->GetIdentHash(), DataI);
  if (results.empty()) {
    LogPrint(eLogWarning, "EmailWorker: retrieveIndex: can't find index for: ", ident_hash);
    return {};
  }

  std::map<i2p::data::Tag<32>, pbote::IndexPacket> index_packets;
  // retrieve index packets
  for (const auto& response: results) {
    if (response->type != type::CommN) {
      // ToDo: looks like in case if we got request to ourself, for now we just skip it
      LogPrint(eLogWarning, "EmailWorker: retrieveIndex: got non-response packet in batch, type: ",
               response->type, ", ver: ", unsigned(response->ver));
      continue;
    }

    LogPrint(eLogDebug, "EmailWorker: retrieveIndex: got response from: ", response->from);
    size_t offset = 0;
    uint8_t status;
    uint16_t dataLen;

    std::memcpy(&status, response->payload.data(), sizeof status);
    offset += 1;
    std::memcpy(&dataLen, response->payload.data() + offset, sizeof dataLen);
    offset += 2;
    dataLen = ntohs(dataLen);

    if (status != StatusCode::OK) {
      LogPrint(eLogWarning, "EmailWorker: retrieveIndex: status: ", statusToString(status));
      continue;
    }

    if (dataLen < 4) {
      LogPrint(eLogWarning, "EmailWorker: retrieveIndex: packet without payload, skip parsing");
      continue;
    }

    uint8_t data[dataLen];
    std::memcpy(&data, response->payload.data() + offset, dataLen);

    std::vector<uint8_t> v_data(response->payload.data() + offset, response->payload.data() + offset + dataLen);
    if (DHT_worker.safe(v_data))
      LogPrint(eLogDebug, "EmailWorker: retrieveIndex: save index packet locally");

    auto index_packet = parseIndexPkt(data, dataLen, true);

    if (!index_packet.data.empty()) {
      i2p::data::Tag<32> hash(index_packet.hash);
      index_packets.insert(std::pair<i2p::data::Tag<32>, pbote::IndexPacket>(hash, index_packet));
    } else
      LogPrint(eLogWarning, "EmailWorker: retrieveIndex: index packet without entries");
  }
  LogPrint(eLogDebug, "EmailWorker: retrieveIndex: ", index_packets.size(), " index packets parsed");

  std::vector<pbote::IndexPacket> res;
  res.reserve(index_packets.size());
  for (const auto &packet : index_packets)
    res.push_back(packet.second);

  // save index packets for interrupt case
  // ToDo: check if we have packet locally and sent delete request now
  //for (const auto &index_packet : res)
    //saveIndexPacket(index_packet);

  return res;
}

std::vector<pbote::EmailEncryptedPacket> EmailWorker::retrieveEmailEncryptedPacket(const std::vector<pbote::IndexPacket> &index_packets) {
  // retrieve mail packets
  std::vector<std::shared_ptr<pbote::CommunicationPacket>> responses;
  std::vector<pbote::EmailEncryptedPacket> local_email_packets;

  for (const auto &index : index_packets) {
    for (auto entry : index.data) {
      i2p::data::Tag<32> hash(entry.key);

      auto local_email_packet = DHT_worker.getEmail(hash);
      if (!local_email_packet.empty()) {
        LogPrint(eLogDebug, "EmailWorker: retrieveEmailEncryptedPacket: got local encrypted email for key:",
                 hash.ToBase64());
        EmailEncryptedPacket parsed_local_email_packet = parseEmailEncryptedPkt(local_email_packet.data(),
                                                                                local_email_packet.size(), true);
        if (!parsed_local_email_packet.edata.empty()) {
          local_email_packets.push_back(parsed_local_email_packet);
        }
      }

      auto temp_results = DHT_worker.findAll(hash, DataE);
      responses.insert(responses.end(), temp_results.begin(), temp_results.end());
    }
  }

  LogPrint(eLogDebug, "EmailWorker: retrieveEmailEncryptedPacket: ", responses.size(), " response packets received");

  std::map<i2p::data::Tag<32>, pbote::EmailEncryptedPacket> mail_packets;
  for (const auto& response : responses) {
    if (response->type != type::CommN) {
      // ToDo: looks like in case if we got request to ourself, for now we just skip it
      LogPrint(eLogWarning, "EmailWorker: retrieveIndex: got non-response packet in batch, type: ",
               response->type, ", ver: ", unsigned(response->ver));
      continue;
    }

    size_t offset = 0;
    uint8_t status;
    uint16_t dataLen;

    std::memcpy(&status, response->payload.data(), 1);
    offset += 1;
    std::memcpy(&dataLen, response->payload.data() + offset, 2);
    offset += 2;
    dataLen = ntohs(dataLen);

    if (status != StatusCode::OK) {
      LogPrint(eLogWarning, "EmailWorker: retrieveEmailEncryptedPacket: status: ", statusToString(status));
      continue;
    }

    if (dataLen == 0) {
      LogPrint(eLogWarning, "EmailWorker: retrieveEmailEncryptedPacket: packet without payload, skip parsing");
      continue;
    }
    LogPrint(eLogDebug, "EmailWorker: retrieveEmailEncryptedPacket: got email packet, payload size: ", dataLen);

    uint8_t data[dataLen];
    std::memcpy(&data, response->payload.data() + offset, dataLen);

    std::vector<uint8_t> v_data(response->payload.data() + offset, response->payload.data() + offset + dataLen);
    if (DHT_worker.safe(v_data))
      LogPrint(eLogDebug, "EmailWorker: retrieveEmailEncryptedPacket: save encrypted email packet locally");

    auto parsed_packet = parseEmailEncryptedPkt(data, dataLen, true);
    if (!parsed_packet.edata.empty()) {
      i2p::data::Tag<32> hash(parsed_packet.key);
      mail_packets.insert(std::pair<i2p::data::Tag<32>, pbote::EmailEncryptedPacket>(hash, parsed_packet));
    } else
      LogPrint(eLogWarning, "EmailWorker: retrieveEmailEncryptedPacket: mail packet without entries");
  }
  LogPrint(eLogDebug, "EmailWorker: retrieveEmailEncryptedPacket: parsed mail packets: ", mail_packets.size());

  for (auto local_packet : local_email_packets) {
    i2p::data::Tag<32> hash(local_packet.key);
    mail_packets.insert(std::pair<i2p::data::Tag<32>, pbote::EmailEncryptedPacket>(hash, local_packet));
  }

  LogPrint(eLogDebug, "EmailWorker: retrieveEmailEncryptedPacket: mail packets: ", mail_packets.size());

  std::vector<pbote::EmailEncryptedPacket> res;
  res.reserve(mail_packets.size());
  for (const auto &packet : mail_packets)
    res.push_back(packet.second);

  // save encrypted email packets for interrupt case
  // ToDo: check if we have packet locally and sent delete request now
  //for (const auto &mail_enc_packet : res)
  //  saveEmailEncryptedPacket(mail_enc_packet);

  return res;
}

/*std::vector<pbote::IndexPacket> EmailWorker::loadLocalIndex() {
  // ToDo: move to DHTStorage
  std::string indexPacketPath = pbote::fs::DataDirPath("DHTindex");
  std::vector<std::string> packets_path;
  std::vector<pbote::IndexPacket> indexPackets;
  auto result = pbote::fs::ReadDir(indexPacketPath, packets_path);
  if (result) {
    for (const auto &packet_path : packets_path) {
      std::ifstream file(packet_path, std::ios::binary);

      std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));

      file.close();
      auto indexPacket = parseIndexPkt(bytes.data(), bytes.size(), false);
      if (!indexPacket.data.empty())
        indexPackets.push_back(indexPacket);
    }
    LogPrint(eLogDebug, "EmailWorker: loadLocalIndex: loaded index files: ", indexPackets.size());
    return indexPackets;
  }
  LogPrint(eLogWarning, "EmailWorker: loadLocalIndex: have no index files");
  return {};
}*/

/*std::vector<pbote::EmailEncryptedPacket> EmailWorker::loadLocalEmailEncryptedPacket() {
  // ToDo: move to DHTStorage
  std::string email_packet_path = pbote::fs::DataDirPath("DHTemail");
  std::vector<std::string> packets_path;
  std::vector<pbote::EmailEncryptedPacket> emailPackets;
  auto result = pbote::fs::ReadDir(email_packet_path, packets_path);
  if (result) {
    for (const auto &packet_path : packets_path) {
      std::ifstream file(packet_path, std::ios::binary);
      std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
      file.close();

      auto email_encrypted_packet = parseEmailEncryptedPkt(bytes.data(), bytes.size(), false);
      if (!email_encrypted_packet.edata.empty())
        emailPackets.push_back(email_encrypted_packet);
    }
    LogPrint(eLogDebug, "EmailWorker: loadLocalEmailEncryptedPacket: mails loaded: ", emailPackets.size());
    return emailPackets;
  }
  LogPrint(eLogWarning, "EmailWorker: loadLocalEmailEncryptedPacket: have no mail files");
  return {};
}*/

std::vector<pbote::EmailUnencryptedPacket> EmailWorker::loadLocalIncompletePacket() {
  // ToDo: just for tests, need to implement
  // ToDo: move to ?
  /*std::string indexPacketPath = pbote::fs::DataDirPath("incomplete");
  std::vector<std::string> packets_path;
  std::vector<pbote::EmailUnencryptedPacket> indexPackets;
  auto result = pbote::fs::ReadDir(indexPacketPath, packets_path);
  if (result) {
    for (const auto &packet_path : packets_path) {
      std::ifstream file(packet_path, std::ios::binary);

      std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));

      file.close();
      auto indexPacket = parseEmailUnencryptedPkt(bytes.data(), bytes.size(), false);
      if (!indexPacket.data.empty())
        indexPackets.push_back(indexPacket);
    }
    LogPrint(eLogDebug, "Email: loadLocalIndex: loaded index files: ", indexPackets.size());
    return indexPackets;
  }
  LogPrint(eLogWarning, "Email: loadLocalIndex: have no index files");*/
  return {};
}

std::vector<std::shared_ptr<pbote::Email>> EmailWorker::checkOutbox() {
  LogPrint(eLogDebug, "EmailWorker: checkOutbox: start");

  // outbox - plain text packet
  // ToDo: encrypt all local stored emails
  std::string outboxPath = pbote::fs::DataDirPath("outbox");
  std::vector<std::string> mails_path;
  auto result = pbote::fs::ReadDir(outboxPath, mails_path);

  std::vector<std::shared_ptr<pbote::Email>> emails;
  if (result) {
    for (const auto &mail_path : mails_path) {
      // read mime packet
      std::ifstream file(mail_path, std::ios::binary);
      std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
      file.close();

      pbote::Email mailPacket;
      mailPacket.fromMIME(bytes);
      mailPacket.setPacket();
      mailPacket.compress(pbote::Email::CompressionAlgorithm::UNCOMPRESSED);

      if (!mailPacket.empty()) {
        emails.push_back(std::make_shared<pbote::Email>(mailPacket));
      }
    }
  }

  LogPrint(eLogDebug, "EmailWorker: checkOutbox: found ", emails.size(), " email(s) for send.");

  return emails;
}

std::vector<pbote::Email> EmailWorker::processEmail(const std::vector<pbote::EmailEncryptedPacket> &mail_packets) {
  LogPrint(eLogDebug, "EmailWorker: processEmail: emails for process: ", mail_packets.size());
  std::vector<pbote::Email> emails;

  for (auto enc_mail : mail_packets) {
    std::vector<uint8_t> unecrypted_email_data;
    if (!enc_mail.edata.empty())
      unecrypted_email_data = decryptData(enc_mail.edata.data(), enc_mail.edata.size());

    if (!unecrypted_email_data.empty()) {
      pbote::Email temp_mail(unecrypted_email_data, true);
      if (!temp_mail.verify(enc_mail.delete_hash)) {
        i2p::data::Tag<32> cur_hash(enc_mail.delete_hash);
        LogPrint(eLogError, "EmailWorker: processEmail: email ",  cur_hash.ToBase32(), " is unequal");
        continue;
      }
      if (!temp_mail.empty()) {
        emails.push_back(temp_mail);
      }
    }
  }

  LogPrint(eLogDebug, "EmailWorker: processEmail: processed emails: ", emails.size());
  return emails;
}

/*bool EmailWorker::saveIndexPacket(pbote::IndexPacket packet) {
  i2p::data::Tag<32> hash(packet.hash);
  std::string packetPath = pbote::fs::DataDirPath("DHTindex", hash.ToBase64() + ".dat");
  if (pbote::fs::Exists(packetPath)) {
    return false;
  }
  LogPrint(eLogDebug, "EmailWorker: saveIndexPacket: save packet to ", packetPath);
  std::ofstream file(packetPath, std::ofstream::binary | std::ofstream::out);
  if (!file.is_open()) {
    LogPrint(eLogError, "EmailWorker: saveIndexPacket: can't open file ", packetPath);
    return false;
  }

  file.write(reinterpret_cast<const char *>(&packet.type), sizeof(packet.type));
  file.write(reinterpret_cast<const char *>(&packet.ver), sizeof(packet.ver));
  file.write(reinterpret_cast<const char *>(&packet.hash), sizeof(packet.hash));
  file.write(reinterpret_cast<const char *>(&packet.nump), sizeof(packet.nump));
  for (auto item : packet.data)
    file.write(reinterpret_cast<const char *>(&item), sizeof(pbote::IndexPacket::Entry));

  file.close();
  return true;
}*/

/*bool EmailWorker::saveEmailEncryptedPacket(pbote::EmailEncryptedPacket packet) {
  i2p::data::Tag<32> hash(packet.key);
  std::string packetPath = pbote::fs::DataDirPath("DHTemail", hash.ToBase64() + ".dat");
  if (pbote::fs::Exists(packetPath)) {
    return false;
  }
  LogPrint(eLogDebug, "EmailWorker: saveEmailEncryptedPacket: save packet to ", packetPath);
  std::ofstream file(packetPath, std::ofstream::binary | std::ofstream::out);
  if (!file.is_open()) {
    LogPrint(eLogError, "EmailWorker: saveEmailEncryptedPacket: can't open file ", packetPath);
    return false;
  }

  file.write(reinterpret_cast<const char *>(&packet.type), sizeof(packet.type));
  file.write(reinterpret_cast<const char *>(&packet.ver), sizeof(packet.ver));
  file.write(reinterpret_cast<const char *>(&packet.key), sizeof(packet.key));
  file.write(reinterpret_cast<const char *>(&packet.stored_time), sizeof(packet.stored_time));
  file.write(reinterpret_cast<const char *>(&packet.delete_hash), sizeof(packet.delete_hash));
  file.write(reinterpret_cast<const char *>(&packet.alg), sizeof(packet.alg));
  file.write(reinterpret_cast<const char *>(&packet.length), sizeof(packet.length));
  file.write(reinterpret_cast<const char *>(packet.edata.data()), packet.edata.size());

  file.close();
  return true;
}*/

bool EmailWorker::saveEmailInboxPacket(pbote::Email mail) {
  // ToDo: move to Email?
  std::string emailPacketPath = pbote::fs::DataDirPath("inbox", mail.getID().ToBase64() + ".mail");

  if (pbote::fs::Exists(emailPacketPath)) {
    return false;
  }
  LogPrint(eLogDebug, "EmailWorker: saveEmailInboxPacket: save packet to ", emailPacketPath);
  std::ofstream file(emailPacketPath, std::ofstream::binary | std::ofstream::out);
  if (!file.is_open()) {
    LogPrint(eLogError, "EmailWorker: saveEmailInboxPacket: can't open file ", emailPacketPath);
    return false;
  }

  auto bytes = mail.bytes();

  file.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());

  file.close();
  return true;
}

} // namespace kademlia
} // namespace pbote
