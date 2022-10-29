/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <algorithm>

#include "BoteIdentity.h"

namespace pbote
{

///////////////////////////////////////////////////////////////////////////////
// Public Identity
///////////////////////////////////////////////////////////////////////////////

BoteIdentityPublic::BoteIdentityPublic (KeyType keyType)
{
  LogPrint(eLogDebug, "EmailIdentityPublic: Key type: ",
           keyTypeToString (keyType));

  switch (keyType)
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        m_Identity.reset (new ECDHP256Identity ());
        break;
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        m_Identity.reset (new ECDHP521Identity ());
        break;
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        m_Identity.reset (new X25519Identity ());
        break;
      default:
        LogPrint(eLogError, "EmailIdentityPublic: Unsupported key type: ",
                 keyTypeToString(keyType));
    }

  RecalculateIdentHash ();
  /* ToDo
  CreateVerifier();
  */
}

BoteIdentityPublic::BoteIdentityPublic (const uint8_t *cryptoPublicKey,
                                        const uint8_t *signingPublicKey,
                                        KeyType keyType)
{
  size_t cryptoPublicKeyLen, signingPublicKeyLen;
  LogPrint(eLogDebug, "BoteIdentityPublic: Key type: ",
           keyTypeToString (keyType));

  if (keyType == KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC)
    {
      cryptoPublicKeyLen = ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH;
      signingPublicKeyLen = ECDH256_ECDSA256_BYTE_PUBLIC_KEY_LENGTH;

      m_Identity.reset (new ECDHP256Identity ());

      m_Identity->setCryptoPublicKey (cryptoPublicKey, cryptoPublicKeyLen);
      m_Identity->setSigningPublicKey (signingPublicKey, signingPublicKeyLen);
    }
  else if (keyType == KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC)
    {
      cryptoPublicKeyLen = ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH;
      signingPublicKeyLen = ECDH521_ECDSA521_BYTE_PUBLIC_KEY_LENGTH;

      m_Identity.reset (new ECDHP521Identity ());

      m_Identity->setCryptoPublicKey (cryptoPublicKey, cryptoPublicKeyLen);
      m_Identity->setSigningPublicKey (signingPublicKey, signingPublicKeyLen);
    }
  else if (keyType == KEY_TYPE_X25519_ED25519_SHA512_AES256CBC)
    {
      cryptoPublicKeyLen = X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH;
      signingPublicKeyLen = X25519_ED25519_BYTE_PUBLIC_KEY_LENGTH;

      m_Identity.reset (new X25519Identity ());

      m_Identity->setCryptoPublicKey (cryptoPublicKey, cryptoPublicKeyLen);
      m_Identity->setSigningPublicKey (signingPublicKey, signingPublicKeyLen);
    }
  else
    {
      LogPrint(eLogError, "BoteIdentityPublic: Unsupported key type: ",
               keyTypeToString (keyType));
    }

  RecalculateIdentHash ();
  /* ToDo
  CreateVerifier();
  */
}

BoteIdentityPublic &
BoteIdentityPublic::operator= (const BoteIdentityPublic &other)
{
  m_Identity = other.m_Identity;
  m_IdentHash = other.m_IdentHash;

  /* ToDo
  delete m_Verifier;
  m_Verifier = nullptr;
  */

  return *this;
}

bool
BoteIdentityPublic::operator== (const BoteIdentityPublic &other) const
{
  return GetIdentHash() == other.GetIdentHash();
}

void
BoteIdentityPublic::RecalculateIdentHash ()
{
  size_t sz = GetFullLen();
  uint8_t *buf = new uint8_t[sz];

  ToBuffer (buf, sz);
  SHA256 (buf, sz, m_IdentHash);

  delete[] buf;
}

size_t
BoteIdentityPublic::FromBuffer (const uint8_t *buf, size_t len)
{
  if (len < m_Identity->get_identity_size ())
    {
      LogPrint(eLogError, "BoteIdentityPublic: FromBuffer: Buffer is too small: ", len);
      return 0;
    }

  m_Identity->from_buffer (buf, len);
  RecalculateIdentHash ();

  /* ToDo
  delete m_Verifier;
  m_Verifier = nullptr;
   */

  return GetFullLen ();
}

size_t
BoteIdentityPublic::ToBuffer (uint8_t *buf, size_t len) const
{
  const size_t fullLen = GetFullLen ();

  if (fullLen > len)
    return 0; // buffer overflow

  return m_Identity->to_buffer (buf, len);
}

size_t
BoteIdentityPublic::FromBase64 (const std::string &s)
{
  const size_t slen = s.length ();
  std::vector<uint8_t> buf (slen); // binary data can't exceed base64

  const size_t l = i2p::data::Base64ToByteStream (s.c_str(), s.length(), buf.data(), slen);

  return FromBuffer (buf.data(), l);
}

std::string
BoteIdentityPublic::ToBase64 () const
{
  const size_t bufLen = GetFullLen ();
  const size_t strLen = i2p::data::Base64EncodingBufferSize (bufLen);
  std::vector<uint8_t> buf (bufLen);
  std::vector<char> str (strLen);
  size_t l = ToBuffer (buf.data (), bufLen);
  size_t l1 = i2p::data::ByteStreamToBase64 (buf.data (), l, str.data (), strLen);

  return std::string(str.data (), l1);
}

std::string
BoteIdentityPublic::ToBase64v1 () const
{
  const size_t bufLen = GetFullLen ();
  const size_t strLen = i2p::data::Base64EncodingBufferSize (bufLen + 5);
  std::vector<uint8_t> data (bufLen);
  std::vector<char> str (strLen);
  size_t l = ToBuffer (data.data(), bufLen);

  std::vector<uint8_t> buf;


  switch(GetKeyType ())
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        {
          uint8_t temp_2[5] = {ADDRESS_FORMAT_V1,
                               CRYP_TYPE_ECDH256,
                               SIGN_TYPE_ECDSA256,
                               SYMM_TYPE_AES_256,
                               HASH_TYPE_SHA_256};
          buf = std::vector<uint8_t>(std::begin (temp_2), std::end (temp_2));
          break;
        }
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        {
          uint8_t temp_3[5] = {ADDRESS_FORMAT_V1,
                               CRYP_TYPE_ECDH521,
                               SIGN_TYPE_ECDSA521,
                               SYMM_TYPE_AES_256,
                               HASH_TYPE_SHA_512};
          buf = std::vector<uint8_t>(std::begin (temp_3), std::end (temp_3));
          break;
        }
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        {
          uint8_t temp_4[5] = {ADDRESS_FORMAT_V1,
                               CRYP_TYPE_X25519,
                               SIGN_TYPE_ED25519,
                               SYMM_TYPE_AES_256,
                               HASH_TYPE_SHA_512};
          buf = std::vector<uint8_t>(std::begin (temp_4), std::end (temp_4));
          break;
        }
      default:
        return {};
    }

  buf.insert (buf.end (), data.begin (), data.end ());

  size_t l1 = i2p::data::ByteStreamToBase64 (buf.data (), l + 5,
                                             str.data (), strLen);

  return { str.data (), l1 };
}

size_t
BoteIdentityPublic::GetSignatureLen () const
{
  /* ToDo
  if (!m_Verifier)
    CreateVerifier();

  if (m_Verifier)
    return m_Verifier->GetSignatureLen();
  */
  return 0;
}

std::vector<uint8_t>
BoteIdentityPublic::Encrypt (const uint8_t *data, int len, const uint8_t *pubKey) const
{
  auto encryptor = CreateEncryptor (pubKey);
  if (encryptor)
    return encryptor->Encrypt (data, len);
  return {};
}

std::shared_ptr<pbote::CryptoKeyEncryptor>
BoteIdentityPublic::CreateEncryptor (const uint8_t *key) const
{
  if (!key)
    key = GetCryptoPublicKey ();
  return CreateEncryptor (GetKeyType (), key);
}

std::shared_ptr<pbote::CryptoKeyEncryptor>
BoteIdentityPublic::CreateEncryptor (const KeyType keyType, const uint8_t *key)
{
  LogPrint (eLogDebug, "BoteIdentityPublic: CreateEncryptor: Crypto key type: ",
            keyTypeToString (keyType));
  switch (keyType)
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        return std::make_shared<pbote::ECDHP256Encryptor>(key);
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        return std::make_shared<pbote::ECDHP521Encryptor>(key);
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        return std::make_shared<pbote::X25519Encryptor>(key);
      default:
        LogPrint (eLogError, "BoteIdentityPublic: CreateEncryptor: Unsupported crypto key type ",
                  keyTypeToString (keyType));
    }
  return nullptr;
}

bool
BoteIdentityPublic::Verify (const uint8_t *buf, size_t len, const uint8_t *signature) const
{
  if (!m_Verifier)
    CreateVerifier ();

  if (m_Verifier)
    return m_Verifier->Verify (buf, len, signature);

  return false;
}

i2p::crypto::Verifier *
BoteIdentityPublic::CreateVerifier (KeyType keyType)
{
  switch (keyType)
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ECDSAP256Verifier ();
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ECDSAP521Verifier ();
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ED25519Verifier ();
      default:
        LogPrint (eLogError, "BoteIdentityPublic: CreateVerifier: Unsupported signing key type ",
                  keyTypeToString (keyType));
    }

  return nullptr;
}

void
BoteIdentityPublic::DropVerifier () const
{
  i2p::crypto::Verifier *verifier;

  {
    std::lock_guard<std::mutex> l(m_VerifierMutex);
    verifier = m_Verifier;
    m_Verifier = nullptr;
  }

  delete verifier;
}

void
BoteIdentityPublic::CreateVerifier () const
{
  if (m_Verifier)
    return; // don't create again

  auto verifier = CreateVerifier (GetKeyType());
  if (verifier)
    verifier->SetPublicKey (m_Identity->getSigningPublicKey ());

  UpdateVerifier (verifier);
}

void
BoteIdentityPublic::UpdateVerifier (i2p::crypto::Verifier *verifier) const
{
  bool del = false;

  {
    std::lock_guard<std::mutex> l(m_VerifierMutex);
    if (!m_Verifier)
      m_Verifier = verifier;
    else
      del = true;
  }

  if (del)
    delete verifier;
}

///////////////////////////////////////////////////////////////////////////////
// Private Identity
///////////////////////////////////////////////////////////////////////////////

BoteIdentityPrivate::BoteIdentityPrivate (KeyType type)
{
  m_Public.reset (new BoteIdentityPublic (type));
}

BoteIdentityPrivate &
BoteIdentityPrivate::operator= (const BoteIdentityPrivate &other)
{
  m_Public = std::make_shared<BoteIdentityPublic>(*other.m_Public);

  setCryptoPrivateKey (other.GetCryptoPrivateKey (),
                       other.getCryptoPrivateKeyLen ());
  setSigningPrivateKey (other.GetSigningPrivateKey (),
                        other.getSigningPrivateKeyLen ());

  /* ToDo
  m_Signer = nullptr;
  CreateSigner();
  */

  return *this;
}

bool
BoteIdentityPrivate::operator== (const BoteIdentityPrivate &other) const
{
  return GetIdentHash() == other.GetIdentHash();
}

size_t
BoteIdentityPrivate::FromBuffer (const uint8_t *buf, size_t len)
{
  m_Public = std::make_shared<BoteIdentityPublic>(GetKeyType ());
  size_t ret = m_Public->FromBuffer (buf, len);

  auto cryptoKeyLen = getCryptoPrivateKeyLen ();

  if (!ret || ret + cryptoKeyLen > len)
    return 0; // overflow

  setCryptoPrivateKey (buf + ret, cryptoKeyLen);
  ret += cryptoKeyLen;

  size_t signingPrivateKeySize = getSigningPrivateKeyLen ();
  if (signingPrivateKeySize + ret > len)
    return 0; // overflow

  setSigningPrivateKey (buf + ret, signingPrivateKeySize);
  ret += signingPrivateKeySize;

  /* ToDo
  m_Signer = nullptr;
  // check if signing private key is all zeros
  bool allzeros = true;
  for (size_t i = 0; i < signingPrivateKeySize; i++)
    if (GetSigningPrivateKey()[i]) {
      allzeros = false;
      break;
    }

  if (allzeros) {
    std::unique_ptr<i2p::crypto::Verifier> transientVerifier(BoteIdentityPublic::CreateVerifier(m_Public->GetKeyType()));
    if (!transientVerifier)
      return 0;

    auto keyLen = transientVerifier->GetPublicKeyLen();
    if (keyLen + ret > len)
      return 0;

    transientVerifier->SetPublicKey(buf + ret);
    ret += keyLen;

    if (m_Public->GetSignatureLen() + ret > len)
      return 0;

    ret += m_Public->GetSignatureLen();
    CreateSigner(m_Public->GetKeyType());
  } else
    CreateSigner(m_Public->GetKeyType());
  */

  return ret;
}

size_t
BoteIdentityPrivate::ToBuffer (uint8_t *buf, size_t len) const
{
  if (m_Public->GetIdentity ()->get_identity_full_size () > len)
    return 0; // overflow

  size_t ret = m_Public->ToBuffer (buf, len);

  size_t cryptoKeyLen = getCryptoPrivateKeyLen ();
  memcpy(buf + ret, GetCryptoPrivateKey (), cryptoKeyLen);
  ret += cryptoKeyLen;

  size_t signingKeyLen = getSigningPrivateKeyLen ();
  memcpy(buf + ret, GetSigningPrivateKey (), signingKeyLen);
  ret += signingKeyLen;

  return ret;
}

size_t
BoteIdentityPrivate::FromBase64 (const std::string &s)
{
  uint8_t *buf = new uint8_t[s.length ()];
  size_t l = i2p::data::Base64ToByteStream (s.c_str (), s.length (),
                                            buf, s.length ());
  LogPrint(eLogDebug, "BoteIdentityPrivate: FromBase64: l: ", l);
  size_t ret = FromBuffer (buf, l);
  delete[] buf;
  return ret;
}

std::string
BoteIdentityPrivate::ToBase64 () const
{
  uint8_t *buf = new uint8_t[GetFullLen ()];
  char *str = new char[GetFullLen () * 2];
  size_t l = ToBuffer (buf, GetFullLen ());
  size_t l1 = i2p::data::ByteStreamToBase64 (buf, l, str, GetFullLen () * 2);
  str[l1] = 0;
  delete[] buf;
  std::string ret(str);
  delete[] str;
  return ret;
}

void
BoteIdentityPrivate::Sign (const uint8_t *buf, int len, uint8_t *signature) const
{
  if (!m_Signer)
    CreateSigner ();

  m_Signer->Sign (buf, len, signature);
}

i2p::crypto::Signer *
BoteIdentityPrivate::CreateSigner (KeyType keyType, const uint8_t *priv)
{
  if (!priv)
    {
      LogPrint (eLogError, "BoteIdentityPrivate: CreateSigner: Empty priv key");
      return nullptr;
    }

  switch (keyType)
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ECDSAP256Signer(priv);
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ECDSAP521Signer(priv);
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        return nullptr;
        // ToDo: return new i2p::crypto::ED25519Signer(priv);
      default:
        LogPrint(eLogError, "BoteIdentityPrivate: CreateSigner: Unsupported signing key type ",
                 keyTypeToString (keyType));
    }
  return nullptr;
}

std::vector<uint8_t>
BoteIdentityPrivate::Decrypt (const uint8_t * encrypted, size_t len)
{
  auto decryptor = CreateDecryptor ();

  if (decryptor)
    return decryptor->Decrypt (encrypted, len);

  return {};
}

std::shared_ptr<pbote::CryptoKeyDecryptor>
BoteIdentityPrivate::CreateDecryptor () const
{
  switch (GetKeyType ())
    {
      case KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC:
        return std::make_shared<pbote::ECDHP256Decryptor>(GetCryptoPrivateKey());
      case KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC:
        return std::make_shared<pbote::ECDHP521Decryptor>(GetCryptoPrivateKey());
      case KEY_TYPE_X25519_ED25519_SHA512_AES256CBC:
        return std::make_shared<pbote::X25519Decryptor>(GetCryptoPrivateKey());
      default:
        LogPrint(eLogError, "BoteIdentityPrivate: CreateDecryptor: Unsupported crypto key type ",
                 keyTypeToString (GetKeyType ()));
    }
  return nullptr;
}

void
BoteIdentityPrivate::CreateSigner (KeyType keyType) const
{
  if (m_Signer)
    return;

  auto signer = CreateSigner (keyType, GetSigningPrivateKey ());
  if (signer)
    m_Signer.reset (signer);
}

} // namespace pbote
