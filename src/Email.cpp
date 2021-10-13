/**
 * Copyright (c) 2019-2021 polistern
 */

#include <cassert>
#include <iostream>
#include <sstream>

#include "BoteContext.h"
#include "Email.h"

namespace pbote {

Email::Email()
  : incomplete_(false),
    empty_(true) {
  setPacket();
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

  // ToDo: rethink
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

  // ToDo: TBD temp
  decompress(packet.data);
  packet.data = body;
  fromMIME(packet.data);
}

Email::~Email() {

}

void Email::fromMIME(const std::vector<uint8_t> &email_data) {
  std::string message(email_data.begin(), email_data.end()), line;
  std::istringstream f(message);
  std::vector<std::string> lines;
  while (std::getline(f, line)) {
    lines.push_back(line);
  }
  for (size_t ln = 0; ln < lines.size(); ln++) {
    for (int i = Header::FROM; i < Header::X_I2PBBOTE_SIGNATURE; i++) {
      if (i == Header::FROM || i == Header::SENDER || i == Header::TO || i == Header::X_I2PBBOTE_SIGNATURE) {
        std::string concat_ln(lines[ln] + lines[ln + 1]);
        std::replace( concat_ln.begin(), concat_ln.end(), '\n', ' ');
        std::string value = getValue(concat_ln, static_cast<Header>(i));
        if (!value.empty()) {
          //LogPrint(eLogDebug, "Email: fromMIME: header: ", HEADER_WHITELIST[i], " lines[ln]: ", lines[ln]);
          //LogPrint(eLogDebug, "Email: fromMIME: header: ", HEADER_WHITELIST[i], " lines[ln + 1]: ", lines[ln + 1]);
          headers.insert(std::pair<Header, std::string>(static_cast<Header>(i), value));
        }
      }
      else {
        std::string value = getValue(lines[ln], static_cast<Header>(i));
        if (!value.empty())
          headers.insert(std::pair<Header, std::string>(static_cast<Header>(i), value));
      }
    }
  }

  for (auto header : headers) {
    LogPrint(eLogDebug, "Email: fromMIME: header: ", HEADER_WHITELIST[header.first], ", value: ", header.second);
  }

  // ToDo: TBD temp
  body = email_data;
  packet.data = email_data;
}

i2p::data::Tag<32> Email::getID() {
  return packet.mes_id;
}

std::vector<uint8_t> Email::getHashCash() {
  // ToDo: think about it
  bool isDone = false;
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

  // ToDo: temp, TBD
  std::string temp_s("1:20:1303030600:admin@example.com::McMybZIhxKXu57jd:FOvXX");
  std::vector<uint8_t> result(temp_s.begin(), temp_s.end());
  return result;
}

std::string Email::getHeader(const std::string &name) {
  for (const auto& header : headers)
    if (name == HEADER_WHITELIST[header.first])
      return header.second;

  return {};
}

void Email::setHeader(Header type, const std::string &value) {
  headers[type] = value;
}

std::map<std::string, std::string> Email::getAllRecipients() {

}

std::string Email::getRecipients(const std::string &type) {

}

std::string Email::getToAddresses() {
  return getHeader(HEADER_WHITELIST[Header::TO]);
}

std::string Email::getCCAddresses() {
  return getHeader(HEADER_WHITELIST[Header::CC]);
}

std::string Email::getBCCAddresses() {
  return getHeader(HEADER_WHITELIST[Header::BCC]);
}

std::string Email::getReplyAddress() {
  return getHeader(HEADER_WHITELIST[Header::REPLY_TO]);
}

bool Email::verify(uint8_t *hash) {
  //i2p::data::Tag<32> ver_hash(hash);
  //i2p::data::Tag<32> cur_hash(packet.DA);
  //LogPrint(eLogDebug, "Email: parseEmailUnencryptedPkt: DA ver_hash: ", ver_hash.ToBase64());
  //LogPrint(eLogDebug, "Email: parseEmailUnencryptedPkt: DA cur_hash: ", cur_hash.ToBase64());
  //if (ver_hash != cur_hash)
  //  LogPrint(eLogError, "Email: parseEmailUnencryptedPkt: hash mismatch, but we try to parse packet");
  return memcmp(hash, packet.DA, 32);
}

std::vector<uint8_t> Email::bytes() {
  // ToDo: TBD temp
  return body;
}

void Email::compress(CompressionAlgorithm type) {
  LogPrint(eLogDebug, "Email: compress: alg: ", unsigned(type));
  if (type == (uint8_t) 1) {
    LogPrint(eLogDebug, "Email: compress: LZMA, start compress");

    std::vector<uint8_t> output;
    lzmaCompress(output, std::vector<uint8_t>(body.data(), body.data() + body.size()));

    packet.data.push_back(uint8_t(1));
    packet.data.insert(packet.data.end(), output.begin(), output.end());
  } else if ((unsigned) type == (uint8_t) 2) {
    LogPrint(eLogDebug, "Email: compress: ZLIB, reserved");
    packet.data.push_back(uint8_t(2));
  } else if ((unsigned) type == (uint8_t) 0) {
    LogPrint(eLogDebug, "Email: compress: data uncompressed, save as is");

    packet.data.push_back(uint8_t(0));
    packet.data.insert(packet.data.end(), body.begin(), body.end());
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
  body = data;
}

void Email::setPacket() {
  // ToDo: just for tests, need to implement
  context.random_cid(packet.mes_id, 32);
  context.random_cid(packet.mes_id, 32);
  context.random_cid(packet.DA, 32);
  context.random_cid(packet.DA, 32);
  packet.fr_id = 0;
  packet.fr_count = 1;
  packet.length = bytes().size();
  packet.data = bytes();
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

std::string Email::getValue(std::string line, Header type) {
  std::string value_delimiter = ": ";
  std::string header = HEADER_WHITELIST[type];
  if (!line.find(header)) {
    size_t pos = 0;
    std::string token;
    while (pos != std::string::npos) {
      pos = line.find(value_delimiter);
      token = line.substr(0, pos);
      line.erase(0, pos + value_delimiter.length() - 1);
    }
    return line;
  } else {
    return {};
  }
}

}