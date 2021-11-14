/**
 * Copyright (c) 2019-2021 polistern
 */

#include <cassert>
#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdio>

#include "BoteContext.h"
#include "Email.h"

namespace pbote {

void *_lzmaAlloc(ISzAllocPtr, size_t size) {
  return new uint8_t[size];
}

void _lzmaFree(ISzAllocPtr, void *addr) {
  if (!addr)
    return;

  delete[] reinterpret_cast<uint8_t *>(addr);
}


ISzAlloc _allocFuncs = {
    _lzmaAlloc, _lzmaFree
};

Email::Email()
  : incomplete_(false),
    empty_(true),
    skip_(false){
  fillPacket();
}

Email::Email(const std::vector<uint8_t> &data, bool from_net) {
  LogPrint(eLogDebug, "Email: Email: payload size: ", data.size());
  /// 72 cause type[1] + ver[1] + mes_id[32] + DA[32] + fr_id[2] + fr_count[2] + length[2]
  if (data.size() < 72) {
    LogPrint(eLogWarning, "Email: Email: payload is too short");
  }

  size_t offset = 0;

  std::memcpy(&packet.type, data.data(), 1);
  offset += 1;
  std::memcpy(&packet.ver, data.data() + offset, 1);
  offset += 1;

  if (packet.type != (uint8_t) 'U') {
    LogPrint(eLogWarning, "Email: Email: wrong packet type: ", packet.type);
  }

  if (packet.ver != (uint8_t) 4) {
    LogPrint(eLogWarning, "Email: Email: wrong packet version: ", unsigned(packet.ver));
  }

  std::memcpy(&packet.mes_id, data.data() + offset, 32);
  offset += 32;
  std::memcpy(&packet.DA, data.data() + offset, 32);
  offset += 32;
  std::memcpy(&packet.fr_id, data.data() + offset, 2);
  offset += 2;
  std::memcpy(&packet.fr_count, data.data() + offset, 2);
  offset += 2;
  std::memcpy(&packet.length, data.data() + offset, 2);
  offset += 2;

  i2p::data::Tag<32> mes_id(packet.mes_id);
  LogPrint(eLogDebug, "Email: Email: mes_id: ", mes_id.ToBase64());

  if (from_net) {
    packet.fr_id = ntohs(packet.fr_id);
    packet.fr_count = ntohs(packet.fr_count);
    packet.length = ntohs(packet.length);
  }

  LogPrint(eLogDebug, "Email: Email: fr_id: ", packet.fr_id, ", fr_count: ", packet.fr_count,
           ", length: ", packet.length);

  if (packet.fr_id >= packet.fr_count) {
    LogPrint(eLogError, "Email: Email: Illegal values, fr_id: ", packet.fr_id, ", fr_count:",
             packet.fr_count);
  }

  incomplete_ = packet.fr_id + 1 != packet.fr_count;
  empty_ = packet.length == 0;

  packet.data = std::vector<uint8_t>(data.data() + offset, data.data() + data.size());

  decompress(packet.data);
  skip_ = false;
  fromMIME(packet.data);
}

Email::~Email() {

}

void Email::fromMIME(const std::vector<uint8_t> &email_data) {
  std::string message(email_data.begin(), email_data.end());
  mail.load(message.begin(), message.end());

  for (const auto& entity : mail.header())
    LogPrint(eLogDebug, "Email: fromMIME: ", entity.name(), ": ", entity.value());

  // ToDo: check all required fields
  empty_ = false;

  packet.data = email_data;
}

i2p::data::Tag<32> Email::getID() {
  return packet.mes_id;
}

std::vector<uint8_t> Email::getHashCash() {
  // ToDo: think about it
  /*bool isDone = false;
  size_t counter = 0;

  uint8_t ver = 1, numb = 20;

  time_t rawtime;
  struct tm *timeinfo;
  char buffer[80];
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  strftime(buffer, sizeof(buffer), "%Y%m%d%H%M%S", timeinfo);
  std::string datetime(buffer);

  //while(!isDone) {

  //}
  */

  // ToDo: temp, TBD
  std::string temp_s("1:20:1303030600:admin@example.com::McMybZIhxKXu57jd:FOvXX");
  std::vector<uint8_t> result(temp_s.begin(), temp_s.end());
  return result;
}

std::map<std::string, std::string> Email::getAllRecipients() {
  return {};
}

std::string Email::getRecipients(const std::string &type) {
  return {};
}

std::string Email::getToAddresses() {
  return mail.header().to().begin()->mailbox().mailbox();
}

std::string Email::getCCAddresses() {
  return mail.header().cc().begin()->mailbox().mailbox();
}

std::string Email::getBCCAddresses() {
  return mail.header().bcc().begin()->mailbox().mailbox();
}

std::string Email::getReplyAddress() {
  return mail.header().replyto().begin()->mailbox().mailbox();
}

bool Email::verify(uint8_t *hash) {
  /* For debug
  i2p::data::Tag<32> ver_hash(hash);
  i2p::data::Tag<32> cur_hash(packet.DA);
  LogPrint(eLogDebug, "Email: parseEmailUnencryptedPkt: DA ver_hash: ", ver_hash.ToBase64());
  LogPrint(eLogDebug, "Email: parseEmailUnencryptedPkt: DA cur_hash: ", cur_hash.ToBase64());
  if (ver_hash != cur_hash)
    LogPrint(eLogError, "Email: parseEmailUnencryptedPkt: hash mismatch, but we try to parse packet");
  */
  return memcmp(hash, packet.DA, 32);
}

std::vector<uint8_t> Email::bytes() {
  std::stringstream buffer;
  buffer << mail;
  std::string str_buf = buffer.str();
  std::vector<uint8_t> result(str_buf.begin(), str_buf.end());

  packet.data = result;
  packet.length = result.size();

  return result;
}

bool Email::save(const std::string& dir) {
  // ToDo: remove all not allowed header fields
  std::string emailPacketPath;
  // If email not loaded from file system, and we need to save it first time
  if (filename().empty() && !dir.empty()) {
    emailPacketPath = pbote::fs::DataDirPath(dir, getID().ToBase64() + ".mail");

    if (pbote::fs::Exists(emailPacketPath)) {
      return false;
    }
  } else {
    emailPacketPath = filename();
  }

  LogPrint(eLogDebug, "Email: save: save packet to ", emailPacketPath);
  std::ofstream file(emailPacketPath, std::ofstream::binary | std::ofstream::out);
  if (!file.is_open()) {
    LogPrint(eLogError, "Email: save: can't open file ", emailPacketPath);
    return false;
  }

  auto message_bytes = bytes();

  file.write(reinterpret_cast<const char *>(message_bytes.data()), message_bytes.size());

  file.close();
  return true;
}

bool Email::move(const std::string& dir) {
  if (skip()) {
    return false;
  }

  std::string new_path = pbote::fs::DataDirPath(dir, field("X-I2PBote-DHT-Key") + ".mail");
  LogPrint(eLogDebug, "Email: move: old path: ", filename());
  LogPrint(eLogDebug, "Email: move: new path: ", new_path);


  std::ifstream ifs(filename(), std::ios::in | std::ios::binary);
  std::ofstream ofs(new_path, std::ios::out | std::ios::binary);
  ofs << ifs.rdbuf();
  int status = std::remove(filename().c_str());

  if (status == 0) {
    LogPrint(eLogInfo, "Email: move: File ", filename(), " moved to ", new_path);
    filename(new_path);
    return true;
  } else {
    LogPrint(eLogError, "Email: move: Can't move file ", filename(), " to ", new_path);
    return false;
  }
}

void Email::compress(CompressionAlgorithm type) {
  LogPrint(eLogDebug, "Email: compress: alg: ", unsigned(type));
  if (type == (uint8_t) 1) {
    LogPrint(eLogDebug, "Email: compress: LZMA, start compress");

    std::vector<uint8_t> output;
    lzmaCompress(output, std::vector<uint8_t>(packet.data.data(), packet.data.data() + packet.data.size()));

    packet.data = std::vector<uint8_t>();
    packet.data.push_back(uint8_t(1));
    packet.data.insert(packet.data.end(), output.begin(), output.end());
  } else if ((unsigned) type == (uint8_t) 2) {
    LogPrint(eLogDebug, "Email: compress: ZLIB, reserved");
    packet.data.push_back(uint8_t(2));
  } else if ((unsigned) type == (uint8_t) 0) {
    LogPrint(eLogDebug, "Email: compress: data uncompressed, save as is");

    std::vector<uint8_t> output;
    output.push_back(uint8_t(0));
    output.insert(output.end(), packet.data.begin(), packet.data.end());

    packet.data = output;
  } else {
    LogPrint(eLogDebug, "Email: compress: Unknown compress algorithm");
  }
}

void Email::decompress(std::vector<uint8_t> v_mail) {
  size_t offset = 0;
  uint8_t compress_alg;
  memcpy(&compress_alg, v_mail.data() + offset, 1);
  offset += 1;

  std::vector<uint8_t> data;

  LogPrint(eLogDebug, "Email: decompress: compress alg: ", unsigned(compress_alg));
  if (compress_alg == (uint8_t) 1) {
    LogPrint(eLogDebug, "Email: decompress: LZMA compressed, start decompress");

    std::vector<uint8_t> output;
    lzmaDecompress(output, std::vector<uint8_t>(v_mail.data() + offset, v_mail.data() + v_mail.size()));
    data = output;
  } else if (compress_alg == (uint8_t) 2) {
    LogPrint(eLogDebug, "Email: decompress: ZLIB compressed, reserved");
  } else if (compress_alg == (uint8_t) 0) {
    LogPrint(eLogDebug, "Email: decompress: data uncompressed, save as is");
    data = std::vector<uint8_t>(v_mail.begin() + 1, v_mail.end());
  } else {
    LogPrint(eLogWarning, "Email: compress: Unknown compress algorithm, try to save as is");
    data = std::vector<uint8_t>(v_mail.begin() + 1, v_mail.end());
  }

  // ToDo: TBD temp
  //body = data;
  mail.load(data.begin(), data.end());
}

void Email::fillPacket() {
  context.random_cid(packet.mes_id, 32);
  context.random_cid(packet.mes_id, 32);
  context.random_cid(packet.DA, 32);
  context.random_cid(packet.DA, 32);

  // ToDo: just for tests, need to implement
  packet.fr_id = 0;
  packet.fr_count = 1;
  packet.length = packet.data.size();

  empty_ = false;
  incomplete_ = false;
}

void Email::lzmaDecompress(std::vector<unsigned char> &outBuf, const std::vector<unsigned char> &inBuf) {
  CLzmaDec dec;

  LzmaDec_Construct(&dec);
  SRes res = LzmaDec_Allocate(&dec, &inBuf[0], LZMA_PROPS_SIZE, &_allocFuncs);
  assert(res == SZ_OK);

  LzmaDec_Init(&dec);

  unsigned outPos = 0, inPos = LZMA_PROPS_SIZE;
  ELzmaStatus status;
  const unsigned long BUF_SIZE = 10240;
  outBuf.resize(25 * 1024 * 1024);

  while (outPos < outBuf.size()) {
    SizeT destLen = std::min(BUF_SIZE, outBuf.size() - outPos);
    SizeT srcLen = std::min(BUF_SIZE, inBuf.size() - inPos);

    res = LzmaDec_DecodeToBuf(&dec,
                              &outBuf[outPos], &destLen,
                              &inBuf[inPos], &srcLen,
                              (outPos + destLen == outBuf.size())
                              ? LZMA_FINISH_END : LZMA_FINISH_ANY, &status);
    assert(res == SZ_OK);
    inPos += srcLen;
    outPos += destLen;
    if (status == LZMA_STATUS_FINISHED_WITH_MARK) {
      LogPrint(eLogDebug, "Email: lzmaDecompress: finished with mark");
      break;
    }
  }

  LzmaDec_Free(&dec, &_allocFuncs);
  outBuf.resize(outPos);
}

void Email::lzmaCompress(std::vector<unsigned char> &outBuf, const std::vector<unsigned char> &inBuf) {

}

} // pbote
