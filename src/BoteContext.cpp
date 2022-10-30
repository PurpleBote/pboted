/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#include <algorithm>
#include <chrono>
#include <utility>

#include "BoteContext.h"
#include "Logging.h"

namespace bote
{

void
identityStorage::init ()
{
  //ToDo: Add file encryption/decryption
  std::string identitiesPath = bote::fs::DataDirPath (DEFAULT_IDENTITY_FILE_NAME);

  LogPrint(eLogInfo, "identityStorage: init: Try load identities from file: ",
           identitiesPath);

  ssize_t nids = load (identitiesPath);
  if (nids == 0)
    {
      LogPrint(eLogWarning,
               "identityStorage: init: Can't load identities from file: ",
               identitiesPath);
    }
  else if (nids < 0)
    {
      LogPrint(eLogWarning,
               "identityStorage: init: Identities file does not exist: ",
               identitiesPath);
    }
  else
    {
      LogPrint(eLogInfo, "identityStorage: init: Loaded identities: ", nids);
    }
}

ssize_t
identityStorage::load (const std::string &path)
{
  // ToDo: Move load to context
  LogPrint(eLogDebug, "identityStorage: load: load identity from file ", path);

  std::string value_delimiter = "=";
  char ident_delimiter = '.';

  // Check if file exist
  std::ifstream file(path);
  if (!file.good ())
    return -1;

  file.close ();

  std::vector<std::string> lines;
  std::vector<std::string> identities;
  std::ifstream infile (path);

  /// Read lines
  for (std::string line; getline (infile, line);)
    {
      /// If start with "identity" - add to parsing
      if (line.rfind (IDENTITY_PREFIX, 0) == 0)
        {
          lines.push_back (line);

          std::string token = line.substr (0, line.find(value_delimiter));
          std::string ident = token.substr (0, line.find(ident_delimiter));

          /// Add only unique identity prefix like "identity0", "identity1", etc.
          auto res = std::find (identities.begin (), identities.end (), ident);
          if (res == identities.end ())
            identities.push_back (ident);
        }

      /// If start with "default" - save to m_default_identity
      if (!line.find (IDENTITY_PREFIX_DEFAULT))
        m_default_identity = line;
    }
  infile.close ();

  /// Now we can start parse values to identities
  for (std::string ident : identities)
    {
      BoteIdentityFull temp_ident;
      temp_ident.id = std::atoi (&ident.back ());

      for (const std::string& line : lines)
        {
          std::string t_ident = ident;
          t_ident.append (".");

          if (line.find (t_ident + IDENTITY_PREFIX_KEY) != std::string::npos)
            {
              temp_ident.full_key = get_param (line, ident,
                                               IDENTITY_PREFIX_KEY);
              continue;
            }

          if (line.find (t_ident + IDENTITY_PREFIX_PUBLIC_NAME) != std::string::npos)
            {
              temp_ident.publicName = get_param (line, ident,
                                                 IDENTITY_PREFIX_PUBLIC_NAME);
              continue;
            }

          if (line.find (t_ident + IDENTITY_PREFIX_DESCRIPTION) != std::string::npos)
            {
              temp_ident.description = get_param (line, ident,
                                                  IDENTITY_PREFIX_DESCRIPTION);
              continue;
            }

          if (line.find (t_ident + IDENTITY_PREFIX_PICTURE) != std::string::npos)
            {
              temp_ident.picture = get_param (line, ident,
                                              IDENTITY_PREFIX_PICTURE);
              continue;
            }

          if (line.find (t_ident + IDENTITY_PREFIX_TEXT) != std::string::npos)
            {
              temp_ident.text = get_param (line, ident, IDENTITY_PREFIX_TEXT);
              continue;
            }
        }

      LogPrint (eLogDebug, "identityStorage: load: name: \"",
                temp_ident.publicName, "\"");
      LogPrint (eLogDebug, "identityStorage: load: full_key: ",
                temp_ident.full_key);
      LogPrint (eLogDebug, "identityStorage: load: description: \"",
                temp_ident.description, "\"");
      //LogPrint (eLogDebug, "identityStorage: load: picture: ",
      //          temp_ident.picture);
      LogPrint (eLogDebug, "identityStorage: load: text: \"",
                temp_ident.text, "\"");
      LogPrint (eLogDebug, "identityStorage: load: size: ",
                temp_ident.full_key.size());

      bool parsed = false;
      std::string format_prefix
        = temp_ident.full_key.substr (0, temp_ident.full_key.find (".") + 1);

      LogPrint (eLogDebug, "identityStorage: load: format_prefix: \"",
                format_prefix, "\"");

      if (format_prefix.compare (ADDRESS_B32_PREFIX) == 0)
        parsed = parse_identity_v1 (&temp_ident);
      else if (format_prefix.compare (ADDRESS_B64_PREFIX) == 0)
        parsed = parse_identity_v1 (&temp_ident);
      else
        parsed = parse_identity_v0 (&temp_ident);

      if (!parsed)
        continue;

      add_identity (temp_ident);
    }
  return (long)identities.size ();
}

void
identityStorage::add_identity (const BoteIdentityFull& ident)
{
  m_identities.push_back (std::make_shared<BoteIdentityFull>(ident));
}

std::vector<std::shared_ptr<BoteIdentityFull>>
identityStorage::get_identities ()
{
  return m_identities;
}

std::string
identityStorage::get_param (std::string line, const std::string& prefix0, const std::string& prefix1)
{
  std::string prefix = prefix0 + "." + prefix1 + "=";
  std::string line_start = line.substr (0, prefix.length ());

  if (line_start.compare (prefix) != 0)
    return {};

  line.erase (0, prefix.length ());

  //LogPrint(eLogDebug, "identityStorage: get_param: prefix: \"", prefix, "\"");
  //LogPrint(eLogDebug, "identityStorage: get_param: line_start: \"", line_start, "\"");
  //LogPrint(eLogDebug, "identityStorage: get_param: line erased: \"", line, "\"");

  return line;
}

bool
identityStorage::parse_identity_v0 (BoteIdentityFull *identity)
{
  size_t base64_key_len = 0, offset = 0;

  if (identity->full_key.length() == ECDH256_ECDSA256_COMPLETE_BASE64_LENGTH)
    {
      identity->identity
        = BoteIdentityPrivate(KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
      base64_key_len = ECDH256_ECDSA256_PUBLIC_BASE64_LENGTH / 2;
    }
  else if (identity->full_key.length() == ECDH521_ECDSA521_COMPLETE_BASE64_LENGTH)
    {
      identity->identity
        = BoteIdentityPrivate(KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC);
      base64_key_len = ECDH521_ECDSA521_PUBLIC_BASE64_LENGTH / 2;
    }
  else
    {
      LogPrint(eLogWarning, "identityStorage: parse_identity_v0: Unsupported identity type");
      return false;
    }

  identity->type = identity->identity.GetKeyType ();
  identity->isDefault = false;
  identity->isPublished = false;

  // Restore keys
  std::string cryptoPublicKey = "A" + identity->full_key.substr(offset, (base64_key_len));
  offset += (base64_key_len);
  std::string signingPublicKey = "A" + identity->full_key.substr(offset, (base64_key_len));
  offset += (base64_key_len);
  std::string cryptoPrivateKey = "A" + identity->full_key.substr(offset, (base64_key_len));
  offset += (base64_key_len);
  std::string signingPrivateKey = "A" + identity->full_key.substr(offset, (base64_key_len));

  std::string restored_identity_str;
  restored_identity_str.append(cryptoPublicKey);
  restored_identity_str.append(signingPublicKey);
  restored_identity_str.append(cryptoPrivateKey);
  restored_identity_str.append(signingPrivateKey);

  identity->identity.FromBase64(restored_identity_str);

  LogPrint(eLogDebug, "identityStorage: parse_identity_v0: identity.ToBase64: ",
           identity->identity.ToBase64());
  LogPrint(eLogDebug, "identityStorage: parse_identity_v0: idenhash.ToBase64: ",
           identity->identity.GetIdentHash().ToBase64());
  LogPrint(eLogDebug, "identityStorage: parse_identity_v0: idenhash.ToBase32: ",
           identity->identity.GetIdentHash().ToBase32());
  LogPrint(eLogDebug, "identityStorage: parse_identity_v0: identity added: ",
           identity->publicName);

  return true;
}

bool
identityStorage::parse_identity_v1 (BoteIdentityFull *identity)
{
  std::string format_prefix = identity->full_key.substr (0, identity->full_key.find (".") + 1);
  std::string base_str = identity->full_key.substr (format_prefix.length ());
  // ToDo: Define length from base32/64
  uint8_t identity_bytes[MAX_IDENTITY_SIZE];
  size_t id_len = 0;

  if (format_prefix.compare (ADDRESS_B32_PREFIX) == 0)
    {
      id_len = i2p::data::Base32ToByteStream (base_str.c_str (),
                                              base_str.length (),
                                              identity_bytes,
                                              MAX_IDENTITY_SIZE);
    }
  else if (format_prefix.compare (ADDRESS_B64_PREFIX) == 0)
    {
      id_len = i2p::data::Base64ToByteStream (base_str.c_str (),
                                              base_str.length (),
                                              identity_bytes,
                                              MAX_IDENTITY_SIZE);
    }
  else
    return false;

  if (id_len < 5)
    {
      LogPrint (eLogError, "identityStorage: parse_identity_v1: Malformed address");
      return false;
    }

  if (identity_bytes[0] != ADDRESS_FORMAT_V1)
    {
      LogPrint (eLogError, "identityStorage: parse_identity_v1: Unsupported address format");
      return false;
    }

  if (identity_bytes[1] == CRYP_TYPE_ECDH256 &&
      identity_bytes[2] == SIGN_TYPE_ECDSA256 &&
      identity_bytes[3] == SYMM_TYPE_AES_256 &&
      identity_bytes[4] == HASH_TYPE_SHA_256)
    {
      identity->identity
        = BoteIdentityPrivate (KEY_TYPE_ECDH256_ECDSA256_SHA256_AES256CBC);
    }
  else if (identity_bytes[1] == CRYP_TYPE_ECDH521 &&
           identity_bytes[2] == SIGN_TYPE_ECDSA521 &&
           identity_bytes[3] == SYMM_TYPE_AES_256 &&
           identity_bytes[4] == HASH_TYPE_SHA_512)
    {
      identity->identity
        = BoteIdentityPrivate (KEY_TYPE_ECDH521_ECDSA521_SHA512_AES256CBC);
    }
  else if (identity_bytes[1] == CRYP_TYPE_X25519 &&
           identity_bytes[2] == SIGN_TYPE_ED25519 &&
           identity_bytes[3] == SYMM_TYPE_AES_256 &&
           identity_bytes[4] == HASH_TYPE_SHA_512)
    {
      identity->identity
        = BoteIdentityPrivate (KEY_TYPE_X25519_ED25519_SHA512_AES256CBC);
    }

  identity->type = identity->identity.GetKeyType ();
  identity->isDefault = false;
  identity->isPublished = false;

  size_t len = identity->identity.FromBuffer (identity_bytes + 5, id_len);

  if (len == 0)
    return false;

  LogPrint(eLogDebug, "identityStorage: parse_identity_v1: identity.ToBase64: ",
           identity->identity.ToBase64 ());
  LogPrint(eLogDebug, "identityStorage: parse_identity_v1: idenhash.ToBase64: ",
           identity->identity.GetIdentHash ().ToBase64 ());
  LogPrint(eLogDebug, "identityStorage: parse_identity_v1: idenhash.ToBase32: ",
           identity->identity.GetIdentHash ().ToBase32 ());
  LogPrint(eLogDebug, "identityStorage: parse_identity_v1: identity added: ",
           identity->publicName);

  return true;
}

/******************************/
BoteContext context;
/******************************/

BoteContext::BoteContext()
{
  m_start_time = ts_now ();

  m_identities_storage = std::make_shared<bote::identityStorage>();

  rbe.seed(time (NULL));
}

BoteContext::~BoteContext()
{
  m_identities_storage = nullptr;
}

void
BoteContext::init()
{
  m_identities_storage->init();

  auto ident_test = m_identities_storage->get_identities();
  LogPrint(eLogInfo, "Context: init: Loaded identities: ", ident_test.size());

  m_address_book.load();
  LogPrint(eLogInfo, "Context: init: Loaded adresses: ", m_address_book.size());
}

sp_bote_id_full
BoteContext::identityByName(const std::string &name)
{
  // ToDo: well is it really better?
  //return std::find_if(email_identities.begin(),
  //                    email_identities.end(),
  //                    [&name](std::shared_ptr<bote::EmailIdentityFull> i){
  //                      return i->publicName == name;
  //                    }).operator*();

  for (auto identity : m_identities_storage->get_identities())
    {
      LogPrint(eLogDebug, "Context: identityByName: name: ", name,
               ", now: ", identity->publicName);
      if (identity->publicName == name)
        return identity;
    }

  return nullptr;
}

std::vector<std::shared_ptr<bote::BoteIdentityFull>>
BoteContext::getEmailIdentities()
{
  return m_identities_storage->get_identities();
};

bool
BoteContext::name_exist(const std::string &name)
{
  return m_address_book.name_exist(name);
}

bool
BoteContext::alias_exist(const std::string &alias)
{
  return m_address_book.alias_exist(alias);
}

std::string
BoteContext::address_for_name(const std::string &name)
{
  return m_address_book.address_for_name(name);
}

std::string
BoteContext::address_for_alias(const std::string &alias)
{
  return m_address_book.address_for_alias(alias);
}

int32_t
BoteContext::get_uptime()
{
  // ToDo: libi2pd Timestamp.h
  return ts_now () - m_start_time;
  //return raw_uptime * std::chrono::system_clock::period::num / 
  //  std::chrono::system_clock::period::den;
}

void
BoteContext::random_cid(uint8_t *buf, size_t len)
{
  std::vector<uint8_t> cid_data(len);
  std::generate(cid_data.begin(), cid_data.end(), std::ref(rbe));
  memcpy(buf, cid_data.data(), len);
}

int32_t
BoteContext::ts_now ()
{
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count ();
}

int64_t
BoteContext::ts_64_now ()
{
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count ();
}

} // namespace bote
