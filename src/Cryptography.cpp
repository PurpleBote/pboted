/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
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

namespace bote
{

ECDHP256Encryptor::ECDHP256Encryptor (const byte *pubkey)
{
  rbe.seed (time (NULL));

  ec_curve = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
  ec_public_point = EC_POINT_new (ec_curve);
  ec_shared_key = create_EC_key (NID_X9_62_prime256v1);

  BIGNUM *bn_public_key = BN_bin2bn (pubkey, ECDHP256_PUB_KEY_SIZE, nullptr);
  EC_POINT_bn2point (ec_curve, bn_public_key, ec_public_point, nullptr);

  if (bn_public_key)
    BN_free (bn_public_key);
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
  int secret_len = 0;
  byte *secret = agree_EC_secret (ec_shared_key, ec_public_point, &secret_len);

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
  int secret_len = 0;
  byte *secret = agree_EC_secret (ec_private_key, ecp_shared_public_point, &secret_len);
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
  ec_shared_key = create_EC_key (NID_secp521r1);

  /// Convert the key to the usuall format
  /// From Java:
  ///   shorten by one byte (bouncyCompressedKey[0] is either 2 or 3,
  ///   bouncyCompressedKey[1] is either 0 or 1, so they can fit in two bits)
  byte pub_unshifted[ECDHP521_PUB_KEY_SIZE];

  memcpy(&pub_unshifted[1], &pubkey[0], ECDHP521_PUB_KEY_SHIFTED_SIZE);

  pub_unshifted[0] = unsigned ((byte)(pub_unshifted[1] | ((pub_unshifted[1] >> 1) + 2)));
  pub_unshifted[1] = unsigned ((byte)(pub_unshifted[1] & 1));

  BIGNUM *bn_public_key = BN_bin2bn (pub_unshifted, ECDHP521_PUB_KEY_SIZE, nullptr);

  if (bn_public_key == nullptr)
    LogPrint (eLogError, "Crypto: ECDHP521Encryptor: Fail to convert bin to BN");

  size_t bn_len = BN_num_bytes(bn_public_key);
  LogPrint (eLogDebug, "Crypto: ECDHP521Encryptor: bn_len: ", bn_len);

  if (!ec_curve || !ec_public_point)
    LogPrint (eLogError, "Crypto: ECDHP521Encryptor: Key or curve are not ready");

  EC_POINT* result = EC_POINT_bn2point (ec_curve, bn_public_key, ec_public_point, nullptr);

  if (result == nullptr)
    LogPrint (eLogError, "Crypto: ECDHP521Encryptor: Point creation failed");

  if (bn_public_key)
    BN_free (bn_public_key);
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
  size_t octets_len = EC_POINT_point2oct (ec_curve, ec_shared_point, POINT_CONVERSION_COMPRESSED,
                                   shared_key, ECDHP521_PUB_KEY_SIZE, nullptr);

  LogPrint (eLogDebug, "Crypto: Encrypt: octets_len: ", octets_len);

  if (0 == octets_len)
    {
      LogPrint (eLogError, "Crypto: Encrypt: Octets len is zero");
      return {};
    }


  /// Write shared point to result data
  std::vector<byte> result (shared_key, shared_key + ECDHP521_PUB_KEY_SIZE);

  /// Create the shared secret from shared point
  int secret_len = 0;
  byte *secret = agree_EC_secret (ec_shared_key, ec_public_point, &secret_len);

  LogPrint (eLogDebug, "Crypto: Encrypt: Secret len: ", secret_len);

  if (secret_len <= 0)
    return {};

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
  ec_curve = EC_GROUP_new_by_curve_name (NID_secp521r1);
  bn_private_key = BN_bin2bn (priv, ECDHP521_PRIV_KEY_SIZE, nullptr);

  if (!ec_curve || !bn_private_key)
    LogPrint (eLogError, "Crypto: ECDHP521Decryptor: Key or curve are not ready");
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
  int secret_len = 0;
  byte *secret = agree_EC_secret (ec_private_key, ecp_shared_public_point, &secret_len);
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

X25519Encryptor::X25519Encryptor (const byte *pubkey)
{
  rbe.seed (time (NULL));

  shared_key = nullptr;
  ctx = EVP_PKEY_CTX_new_id (NID_X25519, nullptr);

  EVP_PKEY_keygen_init (ctx);
  EVP_PKEY_keygen (ctx, &shared_key);

  public_key = EVP_PKEY_new_raw_public_key (EVP_PKEY_X25519, nullptr,
                                            pubkey, X25519_PUB_KEY_SIZE);

  EVP_PKEY_CTX_free(ctx);

  if (!shared_key || !public_key)
    LogPrint (eLogError, "Crypto: X25519Encryptor: Key or context are not ready");
}

X25519Encryptor::~X25519Encryptor ()
{
  EVP_PKEY_CTX_free (ctx);

  if (public_key)
    EVP_PKEY_free (public_key);

  if (shared_key)
    EVP_PKEY_free (shared_key);
}

std::vector<byte>
X25519Encryptor::Encrypt (const byte *data, int len)
{
  if (!shared_key || !public_key)
    {
      LogPrint (eLogError, "Crypto: Encrypt: Key or context are not ready");
      return {};
    }

  /// Write raw shared key to result data
  size_t key_len = X25519_PUB_KEY_SIZE;
  uint8_t raw_shared_key[X25519_PUB_KEY_SIZE];
  EVP_PKEY_get_raw_public_key (shared_key, raw_shared_key, &key_len);
  std::vector<byte> result (raw_shared_key, raw_shared_key + X25519_PUB_KEY_SIZE);

  /// Create the shared secret
  ctx = EVP_PKEY_CTX_new(shared_key, nullptr);

  if (!ctx)
    {
      LogPrint (eLogError, "Crypto: Encrypt: CTX is empty");
      return {};
    }

  if (EVP_PKEY_derive_init(ctx) <= 0)
    {
      LogPrint (eLogError, "Crypto: Encrypt: EVP derive initialization failed");
      return {};
    }

  if (EVP_PKEY_derive_set_peer(ctx, public_key) <= 0)
    {
      LogPrint (eLogError, "Crypto: Encrypt: EVP derive set peer failed");
      return {};
    }

  size_t secret_len = 0;
  byte *secret;

  if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0)
    {
      LogPrint (eLogError, "Crypto: Encrypt: EVP derive failed");
      return {};
    }

  if (nullptr == (secret = static_cast<byte *> (OPENSSL_malloc (secret_len))))
    {
      LogPrint(eLogError, "Crypto: Encrypt: Failed to allocate memory for secret");
      return {};
    }

  if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0)
    {
      LogPrint (eLogError, "Crypto: Encrypt: Shared key derivation failed");
      return {};
    }

  LogPrint (eLogDebug, "Crypto: Encrypt: Secret len: ", secret_len);

  if (secret_len <= 0)
    return {};

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

X25519Decryptor::X25519Decryptor (const byte *priv)
{
  shared_key = nullptr;
  private_key = EVP_PKEY_new_raw_private_key (EVP_PKEY_X25519, nullptr, priv, X25519_PRIV_KEY_SIZE);
  ctx = EVP_PKEY_CTX_new (private_key, nullptr);

  if (!private_key || !ctx)
    LogPrint (eLogError, "Crypto: X25519Decryptor: Key or context are not ready");
}

X25519Decryptor::~X25519Decryptor ()
{
  EVP_PKEY_CTX_free (ctx);

  if (private_key)
    EVP_PKEY_free (private_key);

  if (shared_key)
    EVP_PKEY_free (shared_key);
}

std::vector<byte>
X25519Decryptor::Decrypt (const byte *encrypted, int elen)
{
  if (!private_key || !ctx)
    {
      LogPrint (eLogError, "Crypto: Decrypt: Key or context are not ready");
      return {};
    }

  /// Read the shared public key from data
  size_t offset = 0;
  byte raw_shared_key[X25519_PUB_KEY_SIZE];
  memcpy (raw_shared_key, encrypted, X25519_PUB_KEY_SIZE);
  offset += X25519_PUB_KEY_SIZE;

  /// Convert raw key to key
  shared_key = EVP_PKEY_new_raw_public_key (EVP_PKEY_X25519, nullptr,
                                            raw_shared_key, X25519_PUB_KEY_SIZE);

  /// Re-construct the shared secret
  if (!ctx)
    {
      LogPrint (eLogError, "Crypto: Encrypt: CTX is empty");
      return {};
    }

  if (EVP_PKEY_derive_init(ctx) <= 0)
    {
      LogPrint (eLogError, "Crypto: Decrypt: EVP derive initialization failed");
      return {};
    }

  if (EVP_PKEY_derive_set_peer(ctx, shared_key) <= 0)
    {
      LogPrint (eLogError, "Crypto: Decrypt: EVP derive set peer failed");
      return {};
    }

  size_t secret_len = 0;
  byte *secret;

  if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0)
    {
      LogPrint (eLogError, "Crypto: Decrypt: EVP derive failed");
      return {};
    }

  if (nullptr == (secret = static_cast<byte *> (OPENSSL_malloc (secret_len))))
    {
      LogPrint(eLogError, "Crypto: Decrypt: Failed to allocate memory for secret");
      return {};
    }

  if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0)
    {
      LogPrint (eLogError, "Crypto: Decrypt: Shared key derivation failed");
      return {};
    }

  LogPrint (eLogDebug, "Crypto: Decrypt: Secret len: ", secret_len);

  if (secret_len <= 0)
    return {};

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

} // namespace bote
