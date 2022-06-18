/**
 * Copyright (C) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <algorithm>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "Tag.h"

#include "Cryptography.h"

namespace pbote
{

ECDHP256Encryptor::ECDHP256Encryptor (const byte *pubkey)
{
  rbe.seed (time (NULL));

  ec_curve = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
  ec_public_point = EC_POINT_new (ec_curve);
  ec_shared_key = create_key (NID_X9_62_prime256v1);

  BIGNUM *bn_public_key = BN_bin2bn (pubkey, ECDHP256_PUB_KEY_SIZE, nullptr);
  EC_POINT_bn2point (ec_curve, bn_public_key, ec_public_point, nullptr);
}

ECDHP256Encryptor::~ECDHP256Encryptor ()
{
  if (ec_curve)
    EC_GROUP_free (ec_curve);

  if (ec_public_point)
    EC_POINT_free (ec_public_point);

  if (ec_shared_key)
    EC_KEY_free (ec_shared_key);
}

std::vector<byte>
ECDHP256Encryptor::Encrypt (const byte *data, int len)
{
  if (!ec_curve || !ec_public_point)
    {
      LogPrint (eLogError, "Crypto: Encrypt: Key or curve are not ready");
      return {};
    }

  /// Get shared point
  const EC_POINT* ec_shared_point = EC_KEY_get0_public_key (ec_shared_key);
  byte shared_key[ECDHP256_PUB_KEY_SIZE];
  EC_POINT_point2oct (ec_curve, ec_shared_point, POINT_CONVERSION_COMPRESSED,
                      shared_key, ECDHP256_PUB_KEY_SIZE, nullptr);

  /// Write shared point to result data
  std::vector<byte> result (shared_key, shared_key + ECDHP256_PUB_KEY_SIZE);

  /// Create the shared secret from shared point
  int secret_len;
  byte *secret = get_secret (ec_shared_key, ec_public_point, &secret_len);

  if (secret_len <= 0)
    return {};

  LogPrint (eLogDebug, "Crypto: Encrypt: Secret len: ", secret_len);

  /// Generate hash of shared secret
  std::vector<byte> secret_hash (secret_len);
  SHA256 (secret, secret_len, secret_hash.data ());
  OPENSSL_free (secret);

  i2p::data::Tag<32> secret_h (secret_hash.data ());
  LogPrint (eLogDebug, "Crypto: Encrypt: secret_hash: ", secret_h.ToBase64 ());

  /// Encrypt the data using the hash of the shared secret as an AES key
  byte ivec[AES_BLOCK_SIZE];
  std::generate (ivec, ivec + AES_BLOCK_SIZE, std::ref (rbe));
  result.insert (result.end (), ivec, ivec + AES_BLOCK_SIZE);

  const int padding = len % 16;

  LogPrint (eLogDebug, "Crypto: Encrypt: len: ", len, ", padding: ", padding);

  std::vector<byte> pdata (data, data + len),
    encrypted (len + padding);
  aes_encrypt (secret_hash.data (), ivec, pdata, encrypted);

  LogPrint (eLogDebug, "Crypto: Encrypt: Encrypted size: ", encrypted.size ());

  result.insert (result.end (), encrypted.begin (), encrypted.end ());

  return result;
}

ECDHP256Decryptor::ECDHP256Decryptor (const byte *priv)
{
  ec_curve = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
  bn_private_key = BN_bin2bn (priv, ECDHP256_PRIV_KEY_SIZE, nullptr);
}

ECDHP256Decryptor::~ECDHP256Decryptor ()
{
  if (ec_curve)
    EC_GROUP_free (ec_curve);

  if (bn_private_key)
    BN_free (bn_private_key);
}

std::vector<byte>
ECDHP256Decryptor::Decrypt (const byte *encrypted, int elen)
{
  if (!ec_curve || !bn_private_key)
    {
      LogPrint (eLogError, "Crypto: Decrypt: Key or curve are not ready");
      return {};
    }

  /// Convert BN to private key
  EC_KEY *ec_private_key = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  if (1 != EC_KEY_set_private_key (ec_private_key, bn_private_key))
    {
      LogPrint (eLogError, "Crypto: Decrypt: Fail to convert BN to private key");
      return {};
    }

  /// Read the shared public key
  size_t offset = 0;
  byte shared_key[ECDHP256_PUB_KEY_SIZE];
  memcpy (shared_key, encrypted, ECDHP256_PUB_KEY_SIZE);
  offset += ECDHP256_PUB_KEY_SIZE;

  /// decompress into an EC point
  EC_POINT *ecp_shared_public_point = EC_POINT_new (ec_curve);
  BIGNUM *bn_shared_key = BN_bin2bn (shared_key, ECDHP256_PUB_KEY_SIZE, nullptr);
  EC_POINT_bn2point (ec_curve, bn_shared_key, ecp_shared_public_point, nullptr);
  EC_KEY *shared_ec_key = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);

  /// Make public key from the public point
  if (1 != EC_KEY_set_public_key (shared_ec_key, ecp_shared_public_point))
    {
      LogPrint (eLogError,
        "Crypto: Decrypt: Fail to convert public key to point");
      return {};
    }

  /// Re-construct the shared secret
  int secret_len;
  byte *secret = get_secret (ec_private_key, ecp_shared_public_point, &secret_len);
  if (secret_len <= 0)
    return {};

  LogPrint (eLogDebug, "Crypto: Decrypt: Secret len: ", secret_len);

  /// Get hash of shared secret
  std::vector<byte> secret_hash (secret_len);
  SHA256 (secret, secret_len, secret_hash.data ());
  OPENSSL_free (secret);

  i2p::data::Tag<32> secret_h (secret_hash.data ());
  LogPrint (eLogDebug, "Crypto: Decrypt: Secret_hash: ", secret_h.ToBase64 ());

  /// Decrypt using the shared secret hash as AES key
  byte ivec[AES_BLOCK_SIZE];
  memcpy(ivec, encrypted + offset, AES_BLOCK_SIZE);
  offset += AES_BLOCK_SIZE;

  size_t dlen = elen - offset;
  LogPrint (eLogDebug, "Crypto: Decrypt: elen: ", elen, ", dlen: ", dlen);

  std::vector<byte> edata (encrypted + offset, encrypted + offset + dlen),
    decrypted (dlen);

  aes_decrypt (secret_hash.data (), ivec, edata, decrypted);

  return decrypted;
}

ECDHP521Encryptor::ECDHP521Encryptor (const byte *pubkey)
{
  rbe.seed (time (NULL));

  ec_curve = EC_GROUP_new_by_curve_name (NID_secp521r1);

  ec_public_point = EC_POINT_new (ec_curve);
  ec_shared_key = create_key (NID_secp521r1);

  BIGNUM *bn_public_key = BN_bin2bn (pubkey, ECDHP521_PUB_KEY_SIZE, nullptr);
  EC_POINT_bn2point (ec_curve, bn_public_key, ec_public_point, nullptr);
}

ECDHP521Encryptor::~ECDHP521Encryptor ()
{
  if (ec_curve)
    EC_GROUP_free (ec_curve);

  if (ec_public_point)
    EC_POINT_free (ec_public_point);

  if (ec_shared_key)
    EC_KEY_free (ec_shared_key);
}

std::vector<byte>
ECDHP521Encryptor::Encrypt (const byte *data, int len)
{
  if (!ec_curve || !ec_public_point)
    {
      LogPrint (eLogError, "Crypto: Encrypt: Key or curve are not ready");
      return {};
    }

  /// Get shared point
  const EC_POINT* ec_shared_point = EC_KEY_get0_public_key (ec_shared_key);
  byte shared_key[ECDHP521_PUB_KEY_SIZE];
  EC_POINT_point2oct (ec_curve, ec_shared_point, POINT_CONVERSION_COMPRESSED,
                      shared_key, ECDHP521_PUB_KEY_SIZE, nullptr);

  /// Write shared point to result data
  std::vector<byte> result (shared_key, shared_key + ECDHP521_PUB_KEY_SIZE);

  /// Create the shared secret from shared point
  int secret_len;
  byte *secret = get_secret (ec_shared_key, ec_public_point, &secret_len);

  if (secret_len <= 0)
    return {};

  LogPrint (eLogDebug, "Crypto: Encrypt: Secret len: ", secret_len);

  /// Generate hash of shared secret
  std::vector<byte> secret_hash (secret_len);
  SHA256 (secret, secret_len, secret_hash.data ());
  OPENSSL_free (secret);

  i2p::data::Tag<32> secret_h (secret_hash.data ());
  LogPrint (eLogDebug, "Crypto: Encrypt: secret_hash: ", secret_h.ToBase64 ());

  /// Encrypt the data using the hash of the shared secret as an AES key
  byte ivec[AES_BLOCK_SIZE];
  std::generate (ivec, ivec + AES_BLOCK_SIZE, std::ref (rbe));
  result.insert (result.end (), ivec, ivec + AES_BLOCK_SIZE);

  const int padding = len % 16;

  LogPrint (eLogDebug, "Crypto: Encrypt: len: ", len, ", padding: ", padding);

  std::vector<byte> pdata (data, data + len),
    encrypted (len + padding);
  aes_encrypt (secret_hash.data (), ivec, pdata, encrypted);

  LogPrint (eLogDebug, "Crypto: Encrypt: Encrypted size: ", encrypted.size ());

  result.insert (result.end (), encrypted.begin (), encrypted.end ());

  return result;
}

ECDHP521Decryptor::ECDHP521Decryptor (const byte *priv)
{
  /// Key decompressing
  byte priv_decompress[ECDHP521_PRIV_KEY_SIZE];
  memcpy(&priv_decompress[1], priv, ECDHP521_PRIV_KEY_COMPRESSED);
  priv_decompress[0] |= (priv_decompress[1] >> 1) + 2;
  priv_decompress[1] &= 1;

  ec_curve = EC_GROUP_new_by_curve_name (NID_secp521r1);
  bn_private_key = BN_bin2bn (priv_decompress, ECDHP521_PRIV_KEY_SIZE, nullptr);
}

ECDHP521Decryptor::~ECDHP521Decryptor ()
{
  if (ec_curve)
    EC_GROUP_free (ec_curve);

  if (bn_private_key)
    BN_free (bn_private_key);
}

std::vector<byte>
ECDHP521Decryptor::Decrypt (const byte *encrypted, int elen)
{
  if (!ec_curve || !bn_private_key)
    {
      LogPrint (eLogError, "Crypto: Decrypt: Key or curve are not ready");
      return {};
    }

  /// Convert BN to private key
  EC_KEY *ec_private_key = EC_KEY_new_by_curve_name (NID_secp521r1);
  if (1 != EC_KEY_set_private_key (ec_private_key, bn_private_key))
    {
      LogPrint (eLogError, "Crypto: Decrypt: Fail to convert BN to private key");
      return {};
    }

  /// Read the shared public key
  size_t offset = 0;
  byte shared_key[ECDHP521_PUB_KEY_SIZE];
  memcpy (shared_key, encrypted, ECDHP521_PUB_KEY_SIZE);
  offset += ECDHP521_PUB_KEY_SIZE;

  /// decompress into an EC point
  EC_POINT *ecp_shared_public_point = EC_POINT_new (ec_curve);
  BIGNUM *bn_shared_key = BN_bin2bn (shared_key, ECDHP521_PUB_KEY_SIZE, nullptr);
  EC_POINT_bn2point (ec_curve, bn_shared_key, ecp_shared_public_point, nullptr);
  EC_KEY *shared_ec_key = EC_KEY_new_by_curve_name (NID_secp521r1);

  /// Make public key from the public point
  if (1 != EC_KEY_set_public_key (shared_ec_key, ecp_shared_public_point))
    {
      LogPrint (eLogError,
        "Crypto: Decrypt: Fail to convert public key to point");
      return {};
    }

  /// Re-construct the shared secret
  int secret_len;
  byte *secret = get_secret (ec_private_key, ecp_shared_public_point, &secret_len);
  if (secret_len <= 0)
    return {};

  LogPrint (eLogDebug, "Crypto: Decrypt: Secret len: ", secret_len);

  /// Get hash of shared secret
  std::vector<byte> secret_hash (secret_len);
  SHA256 (secret, secret_len, secret_hash.data ());
  OPENSSL_free (secret);

  i2p::data::Tag<32> secret_h (secret_hash.data ());
  LogPrint (eLogDebug, "Crypto: Decrypt: Secret_hash: ", secret_h.ToBase64 ());

  /// Decrypt using the shared secret hash as AES key
  byte ivec[AES_BLOCK_SIZE];
  memcpy(ivec, encrypted + offset, AES_BLOCK_SIZE);
  offset += AES_BLOCK_SIZE;

  size_t dlen = elen - offset;
  LogPrint (eLogDebug, "Crypto: Decrypt: elen: ", elen, ", dlen: ", dlen);

  std::vector<byte> edata (encrypted + offset, encrypted + offset + dlen),
    decrypted (dlen);

  aes_decrypt (secret_hash.data (), ivec, edata, decrypted);

  return decrypted;
}

void
aes_encrypt(const byte key[AES_KEY_SIZE], const byte iv[AES_BLOCK_SIZE],
            const std::vector<byte>& pdata, std::vector<byte>& cdata)
{
  EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
  int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);

  if (rc != 1)
    {
      LogPrint (eLogError, "Crypto: aes_encrypt: EVP_EncryptInit_ex failed");
      cdata = std::vector<byte>();
      return;
    }

  /// Cipher data expands upto AES_BLOCK_SIZE
  cdata.resize(pdata.size() + AES_BLOCK_SIZE);
  int out_len1 = (int)cdata.size();

  rc = EVP_EncryptUpdate(ctx.get(), (byte*)&cdata[0], &out_len1,
                         (const byte*)&pdata[0], (int)pdata.size());

  if (rc != 1)
    {
      LogPrint (eLogError, "Crypto: aes_encrypt: EVP_EncryptUpdate failed");
      cdata = std::vector<byte>();
      return;
    }

  int out_len2 = (int)cdata.size() - out_len1;
  rc = EVP_EncryptFinal_ex(ctx.get(), (byte*)&cdata[0] + out_len1, &out_len2);

  if (rc != 1)
    {
      LogPrint (eLogError, "Crypto: aes_encrypt: EVP_EncryptFinal_ex failed");
      cdata = std::vector<byte>();
      return;
    }

  /// Set cipher data size now that we know it
  cdata.resize(out_len1 + out_len2);
}

void
aes_decrypt(const byte key[AES_KEY_SIZE], const byte iv[AES_BLOCK_SIZE],
            const std::vector<byte>& cdata, std::vector<byte>& pdata)
{
  EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
  int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);

  if (rc != 1)
    {
      LogPrint (eLogError, "Crypto: aes_decrypt: EVP_DecryptInit_ex failed");
      throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

  /// Plain data expands upto AES_BLOCK_SIZE
  pdata.resize(cdata.size() + AES_BLOCK_SIZE);
  int out_len1 = (int)pdata.size();

  rc = EVP_DecryptUpdate(ctx.get(), (byte*)&pdata[0], &out_len1,
                         (const byte*)&cdata[0], (int)cdata.size());
  if (rc != 1)
    {
      LogPrint (eLogError, "Crypto: aes_decrypt: EVP_DecryptUpdate failed");
      pdata = std::vector<byte>();
      return;
    }

  int out_len2 = (int)pdata.size() - out_len1;
  rc = EVP_DecryptFinal_ex(ctx.get(), (byte*)&pdata[0] + out_len1, &out_len2);

  if (rc != 1)
    {
      LogPrint (eLogError, "Crypto: aes_decrypt: EVP_DecryptFinal_ex failed");
      pdata = std::vector<byte>();
      return;
    }

  /// Set plain data size now that we know it
  pdata.resize(out_len1 + out_len2);
}

} // namespace pbote
