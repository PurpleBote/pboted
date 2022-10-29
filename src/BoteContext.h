/**
 * Copyright (C) 2019-2022, polistern
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#pragma once
#ifndef PBOTED_SRC_CONTEXT_H
#define PBOTED_SRC_CONTEXT_H

#include <random>

#include "AddressBook.h"
#include "BoteIdentity.h"

namespace pbote
{

const std::string DEFAULT_IDENTITY_FILE_NAME = "identities.txt";

const std::string IDENTITY_PREFIX = "identity";
const std::string IDENTITY_PREFIX_KEY = "key";
const std::string IDENTITY_PREFIX_PUBLIC_NAME = "publicName";
const std::string IDENTITY_PREFIX_DESCRIPTION = "description";
const std::string IDENTITY_PREFIX_SALT = "salt";
const std::string IDENTITY_PREFIX_PICTURE = "picture";
const std::string IDENTITY_PREFIX_TEXT = "text";
const std::string IDENTITY_PREFIX_PUBLISHED = "published";
const std::string IDENTITY_PREFIX_DEFAULT = "default";
const std::string CONFIGURATION_PREFIX = "configuration.";

struct BoteIdentityFull
{
  uint16_t id;
  std::string salt;
  std::string publicName;
  std::string full_key;
  std::string description;
  std::string picture;
  std::string text;
  KeyType type;
  bool isPublished;
  bool isDefault;
  BoteIdentityPrivate identity;
};

using sp_bote_id_full = std::shared_ptr<BoteIdentityFull>;

class identityStorage
{
 public:
  identityStorage () = default;

  void init ();
  ssize_t load (const std::string &path);
  //ssize_t save ();
  //ssize_t import ();
  //ssize_t export ();

  void add_identity (const BoteIdentityFull& ident);
  //BoteIdentityFull create_identity ();
  std::vector<sp_bote_id_full> get_identities ();
  //BoteIdentityFull get_identity_by_name (std::string name);
  //BoteIdentityFull get_identity_by_key (std::string key);
  //BoteIdentityFull get_default_identity ();

  static std::string get_param (std::string line,
                                const std::string &prefix0,
                                const std::string &prefix1);

 private:
  bool parse_identity_v0 (BoteIdentityFull *identity);
  bool parse_identity_v1 (BoteIdentityFull *identity);

  std::vector<sp_bote_id_full> m_identities;
  std::string m_default_identity;
};

class BoteContext
{
 public:
  BoteContext();
  ~BoteContext();

  void init();

  /// Identities
  size_t get_identities_count() { return getEmailIdentities().size(); }
  std::shared_ptr<pbote::BoteIdentityFull> identityByName(const std::string &name);
  std::vector<std::shared_ptr<pbote::BoteIdentityFull>> getEmailIdentities();

  /// Adressbook
  size_t contacts_size () { return m_address_book.size (); }
  bool name_exist(const std::string &name);
  bool alias_exist(const std::string &alias);
  std::string address_for_name(const std::string &name);
  std::string address_for_alias(const std::string &alias);

  /// Misc
  void random_cid(uint8_t *buf, size_t len);

  int32_t ts_now ();
  int64_t ts_64_now ();
  int32_t get_uptime();

 private:
  uint64_t m_start_time;

  std::shared_ptr<identityStorage> m_identities_storage;
  pbote::AddressBook m_address_book;

  std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t> rbe;
};

extern BoteContext context;

} // namespace pbote

#endif /* PBOTED_SRC_CONTEXT_H */
