/**
 * Copyright (c) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <cassert>
#include <iostream>
#include <fstream>
#include <cstdio>

#include "Gzip.h"

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
      skip_(false),
      deleted_(false) {
  compose();
}

Email::Email(const std::vector<uint8_t> &data, bool from_net)
    : skip_(false),
      deleted_(false) {
  LogPrint(eLogDebug, "Email: Email: payload size: ", data.size());
  /// 72 because type[1] + ver[1] + mes_id[32] + DA[32] + fr_id[2] + fr_count[2] + length[2]
  if (data.size() < 72) {
    LogPrint(eLogWarning, "Email: payload is too short");
  }

  size_t offset = 0;

  std::memcpy(&packet.type, data.data(), 1);
  offset += 1;
  std::memcpy(&packet.ver, data.data() + offset, 1);
  offset += 1;

  if (packet.type != (uint8_t) 'U') {
    LogPrint(eLogWarning, "Email: wrong packet type: ", packet.type);
  }

  if (packet.ver != (uint8_t) 4) {
    LogPrint(eLogWarning, "Email: wrong packet version: ", unsigned(packet.ver));
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
  LogPrint(eLogDebug, "Email: mes_id: ", mes_id.ToBase64());

  if (from_net) {
    packet.fr_id = ntohs(packet.fr_id);
    packet.fr_count = ntohs(packet.fr_count);
    packet.length = ntohs(packet.length);
  }

  LogPrint(eLogDebug, "Email: fr_id: ", packet.fr_id,
           ", fr_count: ", packet.fr_count,
           ", length: ", packet.length);

  if (packet.fr_id >= packet.fr_count) {
    LogPrint(eLogError, "Email: Illegal values, fr_id: ", packet.fr_id,
             ", fr_count:", packet.fr_count);
  }

  incomplete_ = packet.fr_id + 1 != packet.fr_count;
  empty_ = packet.length == 0;
  packet.data = std::vector<uint8_t>(data.data() + offset, data.data() + data.size());
  decompress(packet.data);
  fromMIME(packet.data);
}

void Email::fromMIME(const std::vector<uint8_t> &email_data) {
  std::string message(email_data.begin(), email_data.end());
  mail.load(message.begin(), message.end());

  for (const auto &entity : mail.header()) {
    if (std::find(HEADER_WHITELIST.begin(), HEADER_WHITELIST.end(), entity.name()) != HEADER_WHITELIST.end())
      LogPrint(eLogDebug, "Email: fromMIME: ", entity.name(), ": ", entity.value());
    else {
      mail.header().field(entity.name()).value("");
      LogPrint(eLogDebug, "Email: fromMIME: Forbidden header ", entity.name(), " removed");
    }
  }

  empty_ = false;
  packet.data = email_data;
  compose();
}

void Email::set_message_id() {
  std::string message_id = generate_uuid_v4();
  message_id.append("@bote.i2p");
  setField("Message-ID", message_id);
}

std::string Email::get_message_id() {
  std::string message_id = field("Message-ID");
  if (message_id.empty() || (message_id.size() == 36 && message_id.c_str()[14] != 4)) {
    LogPrint(eLogDebug, "Email: get_message_id: message ID is not 4 version or empty");
    set_message_id();
    message_id = field("Message-ID");
  }

  return message_id;
}

void Email::set_message_id_bytes() {
  std::string message_id = get_message_id();
  std::vector<uint8_t> res;
  const bool dash[] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  for (int i = 0; i < 36; i++) {
    if (dash[i])
      continue;

    res.push_back(message_id.c_str()[i]);
  }
  memcpy(packet.mes_id, res.data(), 32);

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

  LogPrint(eLogDebug, "Email: bytes: buffer << operator:\n", buffer.str());

  std::string str_buf = buffer.str();
  std::vector<uint8_t> result(str_buf.begin(), str_buf.end());

  packet.data = result;
  packet.length = result.size();

  return result;
}

bool Email::save(const std::string &dir) {
  std::string emailPacketPath;
  // If email not loaded from file system, and we need to save it first time
  if (!dir.empty() && filename().empty()) {
    emailPacketPath = pbote::fs::DataDirPath(dir, get_message_id() + ".mail");

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

bool Email::move(const std::string &dir) {
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

void Email::compose() {
  set_message_id();
  set_message_id_bytes();

  bytes();

  LogPrint(eLogDebug, "Email: compose: Message-ID: ", get_message_id());
  LogPrint(eLogDebug, "Email: compose: Message-ID bytes: ", get_message_id_bytes().ToBase64());
  context.random_cid(packet.DA, 32);
  context.random_cid(packet.DA, 32);

  // ToDo
  packet.fr_id = 0;
  packet.fr_count = 1;
  packet.length = packet.data.size();

  empty_ = false;
  incomplete_ = false;
}

bool Email::compress(CompressionAlgorithm type) {
  LogPrint(eLogDebug, "Email: compress: alg: ", unsigned(type));
  if (type == CompressionAlgorithm::LZMA) {
    LogPrint(eLogDebug, "Email: compress: we not support compression LZMA, will be uncompressed");
    type = CompressionAlgorithm::UNCOMPRESSED;
  }

  if (type == CompressionAlgorithm::ZLIB) {
    LogPrint(eLogDebug, "Email: compress: ZLIB, start compress");

    std::vector<uint8_t> output;
    zlibCompress(output, packet.data);

    packet.data.push_back(uint8_t(CompressionAlgorithm::ZLIB));
    packet.data.insert(packet.data.end(), output.begin(), output.end());
    return true;
  }

  if (type == CompressionAlgorithm::UNCOMPRESSED) {
    LogPrint(eLogDebug, "Email: compress: data uncompressed, save as is");
    packet.data.insert(packet.data.begin(), (uint8_t) CompressionAlgorithm::UNCOMPRESSED);
    return true;
  }

  LogPrint(eLogDebug, "Email: compress: Unknown compress algorithm");
  return false;
}

void Email::decompress(std::vector<uint8_t> v_mail) {
  size_t offset = 0;
  uint8_t compress_alg;
  memcpy(&compress_alg, v_mail.data() + offset, 1);
  offset += 1;

  LogPrint(eLogDebug, "Email: decompress: compress alg: ", unsigned(compress_alg));

  if (compress_alg == CompressionAlgorithm::LZMA) {
    LogPrint(eLogDebug, "Email: decompress: LZMA compressed, start decompress");
    std::vector<uint8_t> output;
    lzmaDecompress(output, std::vector<uint8_t>(v_mail.data() + offset, v_mail.data() + v_mail.size()));
    packet.data = output;
  }

  if (compress_alg == CompressionAlgorithm::ZLIB) {
    LogPrint(eLogDebug, "Email: decompress: ZLIB compressed, start decompress");
    std::vector<uint8_t> output;
    zlibDecompress(output, std::vector<uint8_t>(v_mail.data() + offset, v_mail.data() + v_mail.size()));
    packet.data = output;
  }

  if (compress_alg == CompressionAlgorithm::UNCOMPRESSED) {
    LogPrint(eLogDebug, "Email: decompress: data uncompressed, save as is");
    packet.data = std::vector<uint8_t>(v_mail.begin() + 1, v_mail.end());
  }

  LogPrint(eLogWarning, "Email: decompress: Unknown compress algorithm, try to save as is");
  packet.data = std::vector<uint8_t>(v_mail.begin() + 1, v_mail.end());
}

std::string Email::generate_uuid_v4() {
  static std::random_device              rd;
  static std::mt19937                    gen(rd());
  static std::uniform_int_distribution<> dis(0, 15);
  static std::uniform_int_distribution<> dis2(8, 11);

  std::stringstream ss;
  int i;
  ss << std::hex;
  for (i = 0; i < 8; i++)
    ss << dis(gen);

  ss << "-";
  for (i = 0; i < 4; i++)
    ss << dis(gen);

  ss << "-4";
  for (i = 0; i < 3; i++)
    ss << dis(gen);

  ss << "-";
  ss << dis2(gen);
  for (i = 0; i < 3; i++)
    ss << dis(gen);

  ss << "-";
  for (i = 0; i < 12; i++)
    ss << dis(gen);

  return ss.str();
}

void Email::lzmaDecompress(std::vector<uint8_t> &outBuf, const std::vector<uint8_t> &inBuf) {
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

void Email::zlibCompress(std::vector<uint8_t> &outBuf, const std::vector<uint8_t> &inBuf) {
  i2p::data::GzipInflator inflator;
  inflator.Inflate(inBuf.data(), inBuf.size(), outBuf.data(), outBuf.size());
}

void Email::zlibDecompress(std::vector<uint8_t> &outBuf, const std::vector<uint8_t> &inBuf) {
  i2p::data::GzipDeflator deflator;
  deflator.Deflate(inBuf.data(), inBuf.size(), outBuf.data(), outBuf.size());
}

} // pbote
