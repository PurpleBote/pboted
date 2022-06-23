/**
 * Copyright (C) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTE_SRC_CRYPTOGRAPHY_H_
#define PBOTE_SRC_CRYPTOGRAPHY_H_

#include <chrono>
#include <iostream>
#include <limits>
#include <memory>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "Logging.h"

namespace pbote
{

/// AES
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
/// ECDHP256
#define ECDHP256_PRIV_KEY_SIZE 33
#define ECDHP256_PUB_KEY_SIZE 33
/// ECDHP521
#define ECDHP521_PRIV_KEY_SIZE 66
#define ECDHP521_PUB_KEY_SIZE 67
#define ECDHP521_PUB_KEY_SHIFTED_SIZE 66
/// X25519
#define X25519_PRIV_KEY_SIZE 32
#define X25519_PUB_KEY_SIZE 32

typedef uint8_t byte;

using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

class CryptoKeyEncryptor
{
 public:
  virtual ~CryptoKeyEncryptor () {};
  virtual std::vector<byte> Encrypt (const uint8_t *data, int dlen) = 0;
};

class CryptoKeyDecryptor
{
 public:
  virtual ~CryptoKeyDecryptor () {};
  virtual std::vector<byte> Decrypt (const uint8_t *encrypted, int elen) = 0;
  virtual size_t GetPublicKeyLen () const = 0;
};

class ECDHP256Encryptor : public CryptoKeyEncryptor
{
 public:
  ECDHP256Encryptor (const byte *pubkey);
  ~ECDHP256Encryptor () override;
  std::vector<byte> Encrypt (const byte *data, int dlen) override;

 private:
  EC_GROUP *ec_curve;
  EC_POINT *ec_public_point;
  EC_KEY *ec_shared_key;

  std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t> rbe;
};

class ECDHP256Decryptor : public CryptoKeyDecryptor
{
 public:
  ECDHP256Decryptor (const byte *priv);
  ~ECDHP256Decryptor () override;
  std::vector<byte> Decrypt (const byte *encrypted, int elen) override;
  size_t GetPublicKeyLen () const override { return ECDHP256_PUB_KEY_SIZE; };

 private:
  EC_GROUP *ec_curve;
  BIGNUM *bn_private_key;
};

class ECDHP521Encryptor : public CryptoKeyEncryptor
{
 public:
  ECDHP521Encryptor (const byte *pubkey);
  ~ECDHP521Encryptor () override;
  std::vector<byte> Encrypt (const byte *data, int dlen) override;

 private:
  EC_GROUP *ec_curve;
  EC_POINT *ec_public_point;
  EC_KEY *ec_shared_key;

  std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t> rbe;
};

class ECDHP521Decryptor : public CryptoKeyDecryptor
{
 public:
  ECDHP521Decryptor (const byte *priv);
  ~ECDHP521Decryptor () override;
  std::vector<byte> Decrypt (const byte *encrypted, int elen) override;
  size_t GetPublicKeyLen () const override { return ECDHP521_PUB_KEY_SIZE; };

 private:
  EC_GROUP *ec_curve;
  BIGNUM *bn_private_key;
};

class X25519Encryptor : public CryptoKeyEncryptor
{
 public:
  X25519Encryptor (const byte *pubkey);
  ~X25519Encryptor () override;
  std::vector<byte> Encrypt (const byte *data, int dlen) override;

 private:
  EVP_PKEY_CTX * ctx;
  EVP_PKEY * public_key;
  EVP_PKEY * shared_key;

  std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t> rbe;
};

class X25519Decryptor : public CryptoKeyDecryptor
{
 public:
  X25519Decryptor (const byte *priv);
  ~X25519Decryptor () override;
  std::vector<byte> Decrypt (const byte *encrypted, int elen) override;
  size_t GetPublicKeyLen () const override { return X25519_PUB_KEY_SIZE; };

 private:
  EVP_PKEY_CTX * ctx;
  EVP_PKEY * private_key;
  EVP_PKEY * shared_key;
};

inline byte *
agree_EC_secret (EC_KEY *private_key, const EC_POINT *public_key, int *secret_len)
{
  int field_size;
  unsigned char *secret;

  field_size = EC_GROUP_get_degree (EC_KEY_get0_group (private_key));

  if (field_size == 0)
  {
    OPENSSL_free (secret);
    LogPrint (eLogError, "Crypto: agree_EC_secret: Failed to get degree for group");
    return nullptr;
  }

  *secret_len = (field_size + 7) / 8;

  if (nullptr == (secret = static_cast<byte *> (OPENSSL_malloc (*secret_len))))
    {
      LogPrint(eLogError, "Crypto: agree_EC_secret: Failed to allocate memory for secret");
      return nullptr;
    }

  *secret_len = ECDH_compute_key (secret, *secret_len, public_key, private_key, nullptr);

  if (*secret_len < 0)
  {
    OPENSSL_free (secret);
    LogPrint (eLogError, "Crypto: agree_EC_secret: Failed to compute agreement key");
    return nullptr;
  }

  if (*secret_len == 0)
    {
      OPENSSL_free (secret);
      LogPrint (eLogError, "Crypto: agree_EC_secret: Secret have zero length");
      return nullptr;
    }

  return secret;
}

inline EC_KEY *
create_EC_key (int nid)
{
  EC_KEY *key;

  if (nullptr == (key = EC_KEY_new_by_curve_name (nid)))
    {
      LogPrint(eLogError, "Crypto: create_EC_key: Failed to create key curve");
      return nullptr;
    }

  if (1 != EC_KEY_generate_key (key))
    {
      LogPrint (eLogError, "Crypto: create_EC_key: Failed to generate key");
      return nullptr;
    }

  return key;
}

inline bool
bn2buf (const BIGNUM *bn, uint8_t *buf, size_t len)
{
  int offset = len - BN_num_bytes (bn);

  if (offset < 0)
    return false;

  BN_bn2bin (bn, buf + offset);
  memset (buf, 0, offset);

  return true;
}

void aes_encrypt (const byte key[AES_KEY_SIZE], const byte iv[AES_BLOCK_SIZE],
                  const std::vector<byte>& pdata, std::vector<byte>& cdata);
void aes_decrypt (const byte key[AES_KEY_SIZE], const byte iv[AES_BLOCK_SIZE],
                  const std::vector<byte>& cdata, std::vector<byte>& pdata);

} // namespace pbote

#endif //PBOTE_SRC_CRYPTOGRAPHY_H_
