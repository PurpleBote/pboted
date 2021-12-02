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
      startCheckEmailTasks();
      startSendEmailTask();
    }
    m_worker_thread_ = new std::thread([this] { run(); });
  }
}

void EmailWorker::stop() {
  LogPrint(eLogWarning, "EmailWorker: stopping");
  if (started_) {
    started_ = false;
    stopCheckEmailTasks();
    stopSendEmailTask();

    if (m_worker_thread_) {
      m_worker_thread_->join();
      delete m_worker_thread_;
      m_worker_thread_ = nullptr;
    }
  }
  LogPrint(eLogWarning, "EmailWorker: stopped");
}

void EmailWorker::startCheckEmailTasks() {
  if (started_) {
    for (const auto &email_identity: email_identities) {
      // ToDo: move to object?
      LogPrint(eLogInfo, "EmailWorker: start startCheckEmailTasks for identity ", email_identity->publicName);
      auto new_thread = std::make_shared<std::thread>([this, email_identity] { checkEmailTask(email_identity); });
      m_check_email_threads_.push_back(new_thread);
    }
  }
}

bool EmailWorker::stopCheckEmailTasks() {
  LogPrint(eLogInfo, "EmailWorker: stop checkEmailTask");
  for (const auto& thread: m_check_email_threads_) {
    thread->join();
  }
  LogPrint(eLogInfo, "EmailWorker: checkEmailTask stopped");
  return true;
}

void EmailWorker::startSendEmailTask() {
  if (started_) {
    LogPrint(eLogInfo, "EmailWorker: start sendEmailTask");
    m_send_email_thread_ = new std::thread([this] { sendEmailTask(); });
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

std::vector<std::shared_ptr<pbote::Email>> EmailWorker::check_inbox() {
  LogPrint(eLogDebug, "EmailWorker: check_inbox: start");

  // outbox - plain text packet
  // ToDo: encrypt all local stored emails
  std::string outboxPath = pbote::fs::DataDirPath("inbox");
  std::vector<std::string> mails_path;
  auto result = pbote::fs::ReadDir(outboxPath, mails_path);

  std::vector<std::shared_ptr<pbote::Email>> emails;
  if (result) {
    for (const auto &mail_path: mails_path) {
      // read mime packet
      std::ifstream file(mail_path, std::ios::binary);
      std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
      file.close();

      pbote::Email mailPacket;
      mailPacket.fromMIME(bytes);

      if (mailPacket.length() > 0) {
        LogPrint(eLogDebug, "EmailWorker: check_inbox: file loaded: ", mail_path);
      } else {
        LogPrint(eLogWarning, "EmailWorker: check_inbox: can't read file: ", mail_path);
        continue;
      }

      // ToDo: check signature and set header field

      mailPacket.fillPacket();
      mailPacket.filename(mail_path);

      if (!mailPacket.empty()) {
        emails.push_back(std::make_shared<pbote::Email>(mailPacket));
      }
    }
  }

  LogPrint(eLogDebug, "EmailWorker: check_inbox: found ", emails.size(), " email(s).");

  return emails;
}

std::vector<uint8_t> EmailWorker::decryptData(const std::shared_ptr<pbote::EmailIdentityFull>& identity,
                                              std::vector<uint8_t> edata) {
    std::vector<uint8_t> data = identity->identity.Decrypt(edata.data(), edata.size());
    return data;
}

std::vector<uint8_t> EmailWorker::encryptData(const std::shared_ptr<pbote::EmailIdentityFull>& identity,
                                              std::vector<uint8_t> data,
                                              const pbote::EmailIdentityPublic &recipient) {
    std::vector<uint8_t> enc_data = identity->identity.Encrypt(data.data(),
                                                               data.size(),
                                                               recipient.GetEncryptionPublicKey());
    return enc_data;
}

void EmailWorker::run() {
  while (started_) {
    // ToDo: run checkEmailTask for new loaded identities
    auto new_identities = context.getEmailIdentities();
    if (!new_identities.empty()) {
      email_identities = new_identities;
      LogPrint(eLogInfo, "EmailWorker: update identities, now: ", email_identities.size());
    } else {
      LogPrint(eLogWarning, "EmailWorker: have no identities for start");
    }

    if (m_check_email_threads_.empty() && started_ && !new_identities.empty()) {
      LogPrint(eLogDebug, "EmailWorker: checkEmailTask not run, try to start");
      startCheckEmailTasks();
    }

    if (!m_send_email_thread_ && started_ && !new_identities.empty()) {
      LogPrint(eLogDebug, "EmailWorker: sendEmailTask not run, try to start");
      startSendEmailTask();
    }

    std::this_thread::sleep_for(std::chrono::seconds(60));
  }
}

void EmailWorker::checkEmailTask(const std::shared_ptr<pbote::EmailIdentityFull> &email_identity) {
  while (started_) {
    auto index_packets = retrieveIndex(email_identity);

    auto local_index_packet = DHT_worker.getIndex(email_identity->identity.GetPublic()->GetIdentHash());
    if (!local_index_packet.empty()) {
      LogPrint(eLogDebug, "EmailWorker: checkEmailTask: ",
               email_identity->publicName,
               ": got ", local_index_packet.size(),
               " local index packet(s) for identity");

      /// from_net is true, because we save it as is
      pbote::IndexPacket parsed_local_index_packet;
      bool parsed = parsed_local_index_packet.fromBuffer(local_index_packet, true);

      if (parsed && parsed_local_index_packet.data.size() == parsed_local_index_packet.nump) {
        index_packets.push_back(parsed_local_index_packet);
      }
    } else {
      LogPrint(eLogDebug, "EmailWorker: checkEmailTask: ",
               email_identity->publicName,
               ": can't find local index packets for identity");
    }
    LogPrint(eLogDebug, "EmailWorker: checkEmailTask: ",
             email_identity->publicName,
             ": index count: ", index_packets.size());

    auto enc_mail_packets = retrieveEmailPacket(index_packets);
    LogPrint(eLogDebug, "EmailWorker: checkEmailTask: ",
             email_identity->publicName,
             ": mail count: ", enc_mail_packets.size());

    if (!enc_mail_packets.empty()) {
      auto emails = processEmail(email_identity, enc_mail_packets);

      LogPrint(eLogInfo, "EmailWorker: checkEmailTask: ",
               email_identity->publicName,
               ": email(s) processed: ", emails.size());

      // ToDo: check mail signature
      for (auto mail: emails) {
        mail.save("inbox");

        pbote::EmailDeleteRequestPacket delete_email_packet;

        auto email_packet = mail.getDecrypted();
        memcpy(delete_email_packet.DA, email_packet.DA, 32);
        auto enc_email_packet = mail.getEncrypted();
        memcpy(delete_email_packet.key, enc_email_packet.key, 32);

        i2p::data::Tag<32> email_dht_key(enc_email_packet.key);
        i2p::data::Tag<32> email_del_auth(email_packet.DA);

        // We need to remove all received email packets
        // ToDo: check status of responses
        DHT_worker.deleteEmail(email_dht_key, DataE, delete_email_packet);

        // Delete index packets
        // ToDo: add multipart email support
        DHT_worker.deleteIndexEntry(email_identity->identity.GetPublic()->GetIdentHash(),
                                    email_dht_key, email_del_auth);
      }
    } else {
      LogPrint(eLogDebug, "EmailWorker: checkEmailTask: ",
               email_identity->publicName, ": have no emails for process");
    }

    // ToDo: check sent emails status
    //   if nodes sent empty response - mark as deleted (delivered)

    LogPrint(eLogInfo, "EmailWorker: checkEmailTask: ",
             email_identity->publicName, ": Round complete");
    // ToDo: read interval parameter from config
    std::this_thread::sleep_for(std::chrono::seconds(CHECK_EMAIL_INTERVAL));
  }
}

void EmailWorker::incompleteEmailTask() {
  // ToDo: need to implement for multipart mail packets
}

void EmailWorker::sendEmailTask() {
  while (started_) {
    // compress packet with LZMA/ZLIB
    // ToDo: don't forget, for tests sent uncompressed
    //for (auto packet : emailPackets)
    //  lzmaCompress(packet.data, packet.data);
    // ToDo: slice big packet after compress

    std::vector<std::string> nodes;
    auto outbox = checkOutbox();
    if (!outbox.empty()) {
      // Create Encrypted Email Packet
      for (const auto &email: outbox) {
        // ToDo: move to function
        pbote::EmailEncryptedPacket enc_packet;
        auto packet = email->getDecrypted();

        // Get hash of Delete Auth
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Get hash of Delete Auth");
        SHA256(packet.DA, 32, enc_packet.delete_hash);
        i2p::data::Tag<32> del_hash(enc_packet.delete_hash);
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: del_hash: ", del_hash.ToBase64());
        email->setField("X-I2PBote-Delete-Auth-Hash", del_hash.ToBase64());

        // Create recipient
        pbote::EmailIdentityPublic recipient_identity;
        std::string to_address = email->getToAddresses();
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: to_address: ", to_address);
        // Add zeros to beginning
        std::string cryptoPubKey = "A" + to_address.substr(0, 43);
        std::string signingPubKey = "A" + to_address.substr(43, 43);
        to_address = cryptoPubKey + signingPubKey;

        if (recipient_identity.FromBase64(to_address) == 0) {
          LogPrint(eLogWarning, "EmailWorker: sendEmailTask: Can't create identity from \"TO\" header, skip mail");
          email->skip(true);
          continue;
        }

        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: email: recipient hash: ",
                 recipient_identity.GetIdentHash().ToBase64());

        // Get FROM identity
        auto from_name = email->field("From");
        auto identity_name = from_name.substr(0, from_name.find(' '));
        auto identity = pbote::context.identityByName(identity_name);
        // ToDo: sign email
        if (!identity) {
          if (!email_identities.empty()) {
            LogPrint(eLogWarning, "EmailWorker: sendEmailTask: Can't find identity with name: ", identity_name,
                     ", we can use any other for encrypt data.");
            identity = email_identities[0];
          } else {
            LogPrint(eLogError, "EmailWorker: sendEmailTask: Have no identities, stopping send task");
            stopSendEmailTask();
          }
        }

        // Encrypt data
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Encrypt data");
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: packet.data.size: ", packet.data.size());
        auto packet_bytes = packet.toByte();
        enc_packet.edata = encryptData(identity, packet_bytes, recipient_identity);
        enc_packet.length = enc_packet.edata.size();
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: enc_packet.edata.size(): ", enc_packet.edata.size());
        // ToDo: for now only supported ECDH-256 / ECDSA-256
        enc_packet.alg = 2;
        enc_packet.stored_time = 0;

        // Get hash of data + length for DHT key
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Get hash of data + length for DHT key");
        const size_t data_for_hash_len = 2 + enc_packet.edata.size();

        std::vector<uint8_t> data_for_hash = {static_cast<uint8_t>(enc_packet.length >> 8),
                                              static_cast<uint8_t>(enc_packet.length & 0xff)};
        data_for_hash.insert(data_for_hash.end(), enc_packet.edata.begin(), enc_packet.edata.end());

        SHA256(data_for_hash.data(), data_for_hash_len, enc_packet.key);

        i2p::data::Tag<32> dht_key(enc_packet.key);
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: dht_key : ", dht_key.ToBase64());
        email->setField("X-I2PBote-DHT-Key", dht_key.ToBase64());
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: enc_packet.length : ", enc_packet.length);

        email->setEncrypted(enc_packet);
      }

      // Store Encrypted Email Packet
      for (const auto &email: outbox) {
        // ToDo: move to function
        if (email->skip()) {
          continue;
        }

        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Create Store Request packet");
        pbote::StoreRequestPacket store_packet;

        // For now, it's not checking from Java-Bote side
        store_packet.hashcash = email->getHashCash();
        store_packet.hc_length = store_packet.hashcash.size();
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: store_packet.hc_length: ", store_packet.hc_length);

        store_packet.length = email->getEncrypted().toByte().size();
        store_packet.data = email->getEncrypted().toByte();
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: store_packet.length: ", store_packet.length);

        // Send Store Request with Encrypted Email Packet to nodes
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Send Store Request with Encrypted Email Packet to nodes");
        nodes = DHT_worker.store(i2p::data::Tag<32>(email->getEncrypted().key),
                                 email->getEncrypted().type, store_packet);

        /// If have no OK store responses - mark message as skipped
        if (nodes.empty()) {
          email->skip(true);
          LogPrint(eLogWarning, "EmailWorker: sendEmailTask: email not sent");
        } else {
          DHT_worker.safe(email->getEncrypted().toByte());
          LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Email send to ",
                   nodes.size(), " node(s)");
        }
      }

      // Create and store Index Packet
      for (const auto &email: outbox) {
        // ToDo: move to function
        if (email->skip()) {
          continue;
        }

        pbote::IndexPacket new_index_packet;

        // Create recipient
        // ToDo: re-use from previous step
        pbote::EmailIdentityPublic recipient_identity;
        std::string to_address = email->getToAddresses();
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: to_address: ", to_address);
        // Add zeros to beginning
        std::string cryptoPubKey = "A" + to_address.substr(0, 43);
        std::string signingPubKey = "A" + to_address.substr(43, 43);
        to_address = cryptoPubKey + signingPubKey;

        if (recipient_identity.FromBase64(to_address) == 0) {
          LogPrint(eLogWarning, "EmailWorker: sendEmailTask: Can't create identity from \"TO\" header, skip mail");
          email->skip(true);
          continue;
        }

        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: index recipient hash: ",
                 recipient_identity.GetIdentHash().ToBase64());

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
        store_index_packet.hashcash = email->getHashCash();
        store_index_packet.hc_length = store_index_packet.hashcash.size();
        LogPrint(eLogDebug, "EmailWorker: sendEmailTask: store_index_packet.hc_length: ", store_index_packet.hc_length);

        auto index_packet = new_index_packet.toByte();

        store_index_packet.length = index_packet.size();
        store_index_packet.data = index_packet;

        /// Send Store Request with Index Packet to nodes
        nodes = DHT_worker.store(recipient_identity.GetIdentHash(), new_index_packet.type, store_index_packet);

        /// If have no OK store responses - mark message as skipped
        if (nodes.empty()) {
          email->skip(true);
          LogPrint(eLogWarning, "EmailWorker: sendEmailTask: Index not sent");
        } else {
          DHT_worker.safe(new_index_packet.toByte());
          LogPrint(eLogDebug, "EmailWorker: sendEmailTask: Index send to ",
                   nodes.size(), " node(s)");
        }
      }

      for (const auto &email: outbox) {
        // ToDo: move to function
        if (email->skip()) {
          continue;
        }
        email->setField("X-I2PBote-Deleted", "false");
        // Write new metadata before move file to sent
        email->save("");
        email->move("sent");
      }
    }
    // ToDo: read interval parameter from config
    LogPrint(eLogInfo, "EmailWorker: sendEmailTask: Round complete");
    std::this_thread::sleep_for(std::chrono::seconds(SEND_EMAIL_INTERVAL));
  }
}

std::vector<pbote::IndexPacket> EmailWorker::retrieveIndex(const std::shared_ptr<pbote::EmailIdentityFull> &identity) {
  auto identity_hash = identity->identity.GetPublic()->GetIdentHash();
  LogPrint(eLogDebug, "EmailWorker: retrieveIndex: Try to find index for: ", identity_hash.ToBase64());
  // Use findAll rather than findOne because some peers might have an incomplete set of
  // Email Packet keys, and because we want to send IndexPacketDeleteRequests to all of them.

  auto results = DHT_worker.findAll(identity_hash, DataI);
  if (results.empty()) {
    LogPrint(eLogWarning, "EmailWorker: retrieveIndex: can't find index for: ", identity_hash.ToBase64());
    return {};
  }

  std::map<i2p::data::Tag<32>, pbote::IndexPacket> index_packets;
  // retrieve index packets
  for (const auto &response: results) {
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

    std::memcpy(&status, response->payload.data(), 1);
    offset += 1;
    std::memcpy(&dataLen, response->payload.data() + offset, 2);
    offset += 2;
    dataLen = ntohs(dataLen);

    if (status != StatusCode::OK) {
      LogPrint(eLogWarning, "EmailWorker: retrieveIndex: response status: ", statusToString(status));
      continue;
    }

    if (dataLen < 4) {
      LogPrint(eLogWarning, "EmailWorker: retrieveIndex: packet without payload, skip parsing");
      continue;
    }

    std::vector<uint8_t> v_data(response->payload.begin() + offset, response->payload.begin() + offset + dataLen);

    if (DHT_worker.safe(v_data))
      LogPrint(eLogDebug, "EmailWorker: retrieveIndex: save index packet locally");

    pbote::IndexPacket index_packet;
    bool parsed = index_packet.fromBuffer(v_data, true);

    if (parsed && !index_packet.data.empty()) {
      i2p::data::Tag<32> hash(index_packet.hash);
      index_packets.insert(std::pair<i2p::data::Tag<32>, pbote::IndexPacket>(hash, index_packet));
    } else
      LogPrint(eLogWarning, "EmailWorker: retrieveIndex: index packet without entries");
  }
  LogPrint(eLogDebug, "EmailWorker: retrieveIndex: ", index_packets.size(), " index packets parsed");

  std::vector<pbote::IndexPacket> res;
  res.reserve(index_packets.size());
  for (const auto &packet: index_packets)
    res.push_back(packet.second);

  // save index packets for interrupt case
  // ToDo: check if we have packet locally and sent delete request now

  return res;
}

std::vector<pbote::EmailEncryptedPacket> EmailWorker::retrieveEmailPacket(const std::vector<pbote::IndexPacket> &index_packets) {
  // retrieve mail packets
  std::vector<std::shared_ptr<pbote::CommunicationPacket>> responses;
  std::vector<pbote::EmailEncryptedPacket> local_email_packets;

  for (const auto &index: index_packets) {
    for (auto entry: index.data) {
      i2p::data::Tag<32> hash(entry.key);

      auto local_email_packet = DHT_worker.getEmail(hash);
      if (!local_email_packet.empty()) {
        LogPrint(eLogDebug, "EmailWorker: retrieveEmailPacket: got local encrypted email for key:",
                 hash.ToBase64());
        pbote::EmailEncryptedPacket parsed_local_email_packet;
        bool parsed = parsed_local_email_packet.fromBuffer(local_email_packet.data(),
                                                           local_email_packet.size(), true);

        if (parsed && !parsed_local_email_packet.edata.empty()) {
          local_email_packets.push_back(parsed_local_email_packet);
        }
      } else {
        LogPrint(eLogDebug, "EmailWorker: retrieveEmailPacket: can't find local encrypted email for key:",
                 hash.ToBase64());
      }

      auto temp_results = DHT_worker.findAll(hash, DataE);
      responses.insert(responses.end(), temp_results.begin(), temp_results.end());
    }
  }

  LogPrint(eLogDebug, "EmailWorker: retrieveEmailPacket: ", responses.size(), " response packets received");

  std::map<i2p::data::Tag<32>, pbote::EmailEncryptedPacket> mail_packets;
  for (const auto &response: responses) {
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
      LogPrint(eLogWarning, "EmailWorker: retrieveEmailPacket: response status: ", statusToString(status));
      continue;
    }

    if (dataLen == 0) {
      LogPrint(eLogWarning, "EmailWorker: retrieveEmailPacket: packet without payload, skip parsing");
      continue;
    }
    LogPrint(eLogDebug, "EmailWorker: retrieveEmailPacket: got email packet, payload size: ", dataLen);

    std::vector<uint8_t> data = {response->payload.data() + offset,
                                 response->payload.data() + offset + dataLen};

    std::vector<uint8_t> v_data(response->payload.begin() + offset, response->payload.begin() + offset + dataLen);
    if (DHT_worker.safe(v_data))
      LogPrint(eLogDebug, "EmailWorker: retrieveEmailPacket: save encrypted email packet locally");

    pbote::EmailEncryptedPacket parsed_packet;
    bool parsed = parsed_packet.fromBuffer(data.data(), dataLen, true);

    if (parsed && !parsed_packet.edata.empty()) {
      i2p::data::Tag<32> hash(parsed_packet.key);
      mail_packets.insert(std::pair<i2p::data::Tag<32>, pbote::EmailEncryptedPacket>(hash, parsed_packet));
    } else
      LogPrint(eLogWarning, "EmailWorker: retrieveEmailPacket: mail packet without entries");
  }
  LogPrint(eLogDebug, "EmailWorker: retrieveEmailPacket: parsed mail packets: ", mail_packets.size());

  for (auto local_packet: local_email_packets) {
    i2p::data::Tag<32> hash(local_packet.key);
    mail_packets.insert(std::pair<i2p::data::Tag<32>, pbote::EmailEncryptedPacket>(hash, local_packet));
  }

  LogPrint(eLogDebug, "EmailWorker: retrieveEmailPacket: mail packets: ", mail_packets.size());

  std::vector<pbote::EmailEncryptedPacket> res;
  res.reserve(mail_packets.size());
  for (const auto &packet: mail_packets)
    res.push_back(packet.second);

  // save encrypted email packets for interrupt case
  // ToDo: check if we have packet locally and sent delete request now

  return res;
}

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
    for (const auto &mail_path: mails_path) {
      // read mime packet
      std::ifstream file(mail_path, std::ios::binary);
      std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
      file.close();

      pbote::Email mailPacket;
      mailPacket.fromMIME(bytes);

      if (mailPacket.length() > 0) {
        LogPrint(eLogDebug, "EmailWorker: checkOutbox: file loaded: ", mail_path);
      } else {
        LogPrint(eLogWarning, "EmailWorker: checkOutbox: can't read file: ", mail_path);
        continue;
      }

      mailPacket.filename(mail_path);

      // ToDo: need to simplify

      /// Check if if FROM and TO fields have valid public names, else
      /// Check if <name@domain> in AddressBook for replacement
      /// if not found - log warning and skip
      /// if replaced - save modified email to file to keep changes

      std::string from_address = mailPacket.field("From");
      std::string to_address = mailPacket.field("To");
      if (from_address.empty() || to_address.empty()) {
        LogPrint(eLogWarning, "EmailWorker: checkOutbox: FROM or TO field are empty");
        continue;
      }

      bool changed = false;
      std::string et_char("@"), less_char("<");
      size_t from_less_pos = from_address.find(less_char);
      size_t from_et_pos = from_address.find(et_char);
      if (from_less_pos != std::string::npos && from_et_pos != std::string::npos) {
        LogPrint(eLogDebug, "EmailWorker: checkOutbox: try to replace FROM: ",
                 from_address);

        std::string old_from_address = from_address;
        std::string pub_name = from_address.substr(0, from_less_pos - 1);
        from_address.erase(0, from_less_pos + 1);
        from_et_pos = from_address.find(et_char);
        std::string alias_name = from_address.substr(0, from_et_pos);

        auto pub_from_identity = context.identityByName(pub_name);
        auto alias_from_identity = context.identityByName(alias_name);
        if (!pub_from_identity && !alias_from_identity) {
          LogPrint(eLogWarning, "EmailWorker: checkOutbox: can't find address for name:",
                   pub_name, ", alias: ", alias_name);
          continue;
        }
        std::string new_from;
        if (pub_from_identity) {
          std::string pub_str = pub_from_identity->full_key.substr(0, 86);
          new_from.append(
              pub_from_identity->publicName + " <" + pub_str + ">");
        } else if (alias_from_identity) {
          std::string alias_str = alias_from_identity->full_key.substr(0, 86);
          new_from.append(
              alias_from_identity->publicName + " <" + alias_str + ">");
        } else {
          LogPrint(eLogError, "EmailWorker: checkOutbox: unknown error, name:",
                   pub_name, ", alias: ", alias_name);
          continue;
        }
        LogPrint(eLogDebug, "EmailWorker: checkOutbox: FROM replaced, old: ",
                 old_from_address, ", new: ", new_from);
        mailPacket.setField("From", new_from);
        changed = true;
      }

      // Now replace TO
      size_t to_less_pos = to_address.find(less_char);
      size_t to_et_pos = to_address.find(et_char);
      if (to_less_pos != std::string::npos && to_et_pos != std::string::npos) {
        LogPrint(eLogDebug, "EmailWorker: checkOutbox: try to replace TO: ",
                 to_address);

        std::string old_to_address = to_address;
        std::string pub_name = to_address.substr(0, to_less_pos - 1);
        to_address.erase(0, to_less_pos + 1);
        to_et_pos = to_address.find(et_char);
        std::string alias_name = to_address.substr(0, to_et_pos);

        auto pub_to_address = context.address_for_name(pub_name);
        auto alias_to_address = context.address_for_alias(alias_name);

        if (pub_to_address.empty() && alias_to_address.empty()) {
          LogPrint(eLogWarning, "EmailWorker: checkOutbox: can't find address for ",
                   to_address);
          continue;
        }

        std::string new_to;
        if (!pub_to_address.empty()) {
          new_to.append(pub_name + " <" +pub_to_address + ">");
        } else if (!alias_to_address.empty()) {
          new_to.append(alias_name + " <" + pub_to_address + ">");
        } else {
          LogPrint(eLogError, "EmailWorker: checkOutbox: unknown error, name:",
                   pub_name, ", alias: ", alias_name);
          continue;
        }
        LogPrint(eLogDebug, "EmailWorker: checkOutbox: TO replaced, old: ",
                 old_to_address, ", new: ", new_to);
        mailPacket.setField("To", new_to);
        changed = true;
      }

      if (changed)
        mailPacket.save("");


      mailPacket.fillPacket();

      // ToDo: compress
      mailPacket.compress(pbote::Email::CompressionAlgorithm::UNCOMPRESSED);

      if (!mailPacket.empty()) {
        emails.push_back(std::make_shared<pbote::Email>(mailPacket));
      }
    }
  }

  LogPrint(eLogDebug, "EmailWorker: checkOutbox: found ", emails.size(), " email(s) for send.");

  return emails;
}

std::vector<pbote::Email> EmailWorker::processEmail(const std::shared_ptr<pbote::EmailIdentityFull>& identity,
                                                    const std::vector<pbote::EmailEncryptedPacket> &mail_packets) {
  // ToDo: move to incompleteEmailTask?
  LogPrint(eLogDebug, "EmailWorker: processEmail: emails for process: ", mail_packets.size());
  std::vector<pbote::Email> emails;

  for (auto enc_mail: mail_packets) {
    std::vector<uint8_t> unencrypted_email_data;
    if (!enc_mail.edata.empty())
      unencrypted_email_data = decryptData(identity, enc_mail.edata);

    if (!unencrypted_email_data.empty()) {
      pbote::Email temp_mail(unencrypted_email_data, true);
      if (!temp_mail.verify(enc_mail.delete_hash)) {
        i2p::data::Tag<32> cur_hash(enc_mail.delete_hash);
        LogPrint(eLogError, "EmailWorker: processEmail: email ", cur_hash.ToBase32(), " is unequal");
        continue;
      }
      temp_mail.setEncrypted(enc_mail);
      if (!temp_mail.empty()) {
        emails.push_back(temp_mail);
      }
    }
  }

  LogPrint(eLogDebug, "EmailWorker: processEmail: processed emails: ", emails.size());
  return emails;
}

} // namespace kademlia
} // namespace pbote
