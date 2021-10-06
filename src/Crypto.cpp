/**
 * Copyright (c) 2019-2021 polistern
 */

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <algorithm>

#include "Crypto.h"
#include "lib/libi2pd/Tag.h"

namespace pbote {

ECDHP256Encryptor::ECDHP256Encryptor(const byte *pubkey) {
  std::chrono::high_resolution_clock::duration
      d = std::chrono::high_resolution_clock::now() - std::chrono::high_resolution_clock::now();
  unsigned seed2 = d.count();
  rbe.seed(seed2);

  ec_curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  ec_public_point = EC_POINT_new(ec_curve);
  ec_ephemeral_key = create_key();

  BIGNUM *bn_public_key = BN_bin2bn(pubkey, EPH_KEY_LEN, nullptr);
  EC_POINT_bn2point(ec_curve, bn_public_key, ec_public_point, nullptr);
}

ECDHP256Encryptor::~ECDHP256Encryptor() {
  if (ec_curve) EC_GROUP_free(ec_curve);
  if (ec_public_point) EC_POINT_free(ec_public_point);
  if (ec_ephemeral_key) EC_KEY_free(ec_ephemeral_key);
}

std::vector<byte> ECDHP256Encryptor::Encrypt(const byte *data, int len) {
  if (ec_curve && ec_public_point) {

    // Get shared point
    const EC_POINT* ec_eph_point = EC_KEY_get0_public_key(ec_ephemeral_key);
    byte shared_key[EPH_KEY_LEN];
    EC_POINT_point2oct(ec_curve, ec_eph_point, POINT_CONVERSION_COMPRESSED, shared_key, 33, nullptr);
    std::vector<byte> result(shared_key, shared_key + EPH_KEY_LEN);

    // Create the shared secret
    int secret_len;
    byte *secret = get_secret(ec_ephemeral_key, ec_public_point, &secret_len);
    if (secret_len < 0) {
      LogPrint(eLogError, "Crypto: Encrypt: key compute error");
      return {};
    }
    if (secret_len == 0) {
      LogPrint(eLogError, "Crypto: Encrypt: secret len is 0");
      return {};
    }
    LogPrint(eLogDebug, "Crypto: Encrypt: secret len: ", secret_len);

    // Generate hash of shared secret
    byte secret_hash[secret_len];
    SHA256(secret, secret_len, secret_hash);
    OPENSSL_free(secret);

    i2p::data::Tag<32> secret_h(secret_hash);
    LogPrint(eLogDebug, "Crypto: Encrypt: secret_hash: ", secret_h.ToBase64());

    // Encrypt the data using the hash of the shared secret as an AES key
    byte *ivec = new byte[AES_BLOCK_SIZE];
    std::generate(ivec, ivec + AES_BLOCK_SIZE, std::ref(rbe));
    result.insert(result.end(), ivec, ivec + AES_BLOCK_SIZE);

    AES_KEY encrypt_key;
    AES_set_encrypt_key(secret_hash, 256, &encrypt_key);

    LogPrint(eLogDebug, "Crypto: Encrypt: len: ", len, ", pad: ", len % 16);
    len += len % 16;

    byte *encrypted = new byte[len];

    LogPrint(eLogDebug, "Crypto: Encrypt: len: ", len);

    AES_cbc_encrypt(data, encrypted, len, &encrypt_key, ivec, AES_ENCRYPT);

    LogPrint(eLogDebug, "Crypto: Encrypt: len: ", len);

    std::vector<byte> enc_data(encrypted, encrypted + len);
    LogPrint(eLogDebug, "Crypto: Encrypt: enc_data.size(): ", enc_data.size());
    result.insert(result.end(), enc_data.begin(), enc_data.end());

    return result;
  }
  return {};
}

ECDHP256Decryptor::ECDHP256Decryptor(const byte *priv) {
  ec_curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  bn_private_key = BN_bin2bn(priv, 33, nullptr);
}

ECDHP256Decryptor::~ECDHP256Decryptor() {
  if (ec_curve) EC_GROUP_free(ec_curve);
  if (bn_private_key) BN_free(bn_private_key);
}

std::vector<byte> ECDHP256Decryptor::Decrypt(const byte *encrypted, int elen) {
  if (ec_curve && bn_private_key) {
    // convert BN to private key
    EC_KEY *ec_private_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (1 != EC_KEY_set_private_key(ec_private_key, bn_private_key)) {
      LogPrint(eLogError, "Crypto: Decrypt: fail to convert BN to private key");
      return {};
    }

    // read the ephemeral public key - 33 byte
    size_t offset = 0;
    byte ephemeral_key[EPH_KEY_LEN];
    memcpy(ephemeral_key, encrypted, EPH_KEY_LEN);
    offset += EPH_KEY_LEN;

    // decompress into an EC point
    EC_POINT *ecp_eph_public_point = EC_POINT_new(ec_curve);
    BIGNUM *bn_eph_key = BN_bin2bn(ephemeral_key, EPH_KEY_LEN, nullptr);
    EC_POINT_bn2point(ec_curve, bn_eph_key, ecp_eph_public_point, nullptr);
    EC_KEY *eph_ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    // make a public key from the public point
    if (1 != EC_KEY_set_public_key(eph_ec_key, ecp_eph_public_point)) {
      LogPrint(eLogError, "Crypto: Decrypt: fail to convert public key to point");
      return {};
    }

    // reconstruct the shared secret
    int secret_len;
    byte *secret = get_secret(ec_private_key, ecp_eph_public_point, &secret_len);
    if (secret_len < 0) {
      LogPrint(eLogError, "Crypto: Decrypt: key compute error");
      return {};
    }
    if (secret_len == 0) {
      LogPrint(eLogError, "Crypto: Decrypt: secret len is 0");
      return {};
    }
    LogPrint(eLogDebug, "Crypto: Decrypt: secret len: ", secret_len);

    // generate hash of shared secret
    byte secret_hash[secret_len];
    SHA256(secret, secret_len, secret_hash);
    OPENSSL_free(secret);

    i2p::data::Tag<32> secret_h(secret_hash);
    LogPrint(eLogDebug, "Crypto: Decrypt: secret_hash: ", secret_h.ToBase64());

    // decrypt using the shared secret hash as AES key
    byte *ivec = new byte[AES_BLOCK_SIZE];
    memcpy(ivec, encrypted + offset, AES_BLOCK_SIZE);
    offset += AES_BLOCK_SIZE;

    size_t dlen = elen - offset;
    LogPrint(eLogDebug, "Crypto: Decrypt: dlen: ", dlen, ", elen: ", elen);

    byte *edata = new byte[dlen];
    memcpy(edata, encrypted + offset, dlen);

    AES_KEY dkey;
    AES_set_decrypt_key(secret_hash, 256, &dkey);

    byte *decrypted = new byte[dlen];

    AES_cbc_encrypt(edata, decrypted, dlen, &dkey, ivec, AES_DECRYPT);

    std::vector<byte> dec_data(decrypted, decrypted + dlen);
    return dec_data;
  }
  return {};
}

} // namespace pbote