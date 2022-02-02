/**
 * Copyright (C) 2019-2022 polistern
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef PBOTED_SRC_ADDRESS_BOOK_H_
#define PBOTED_SRC_ADDRESS_BOOK_H_

#include <map>
#include <string>
#include <vector>

namespace pbote
{

#define ADDRESS_BOOK_FILE_NAME "addressbook.txt"

struct Contact
{
public:
  Contact () = default;

  std::string alias{};
  std::string name{};
  std::string dest{};
};

class AddressBook
{
public:
  /**
   * @brief Construct a new Address Book object
   * 
   */
  AddressBook ();
  /**
   * @brief Construct a new Address Book object
   * 
   * @param path path to address book file
   * @param pass keyword to decrypt file (optional)
   */
  AddressBook (std::string path, std::string pass);
  ~AddressBook ();

  /**
   * @brief Load and parse aliases after reading from file
   * 
   */
  void load ();
  void save ();

  void add (const std::string &alias,
            const std::string &name,
            const std::string &address);
  bool name_exist (const std::string &name);
  bool alias_exist (const std::string &alias);
  std::string address_for_name (const std::string &name);
  std::string address_for_alias (const std::string &alias);
  void remove (const std::string &name);

  size_t
  size ()
  {
    return contacts.size ();
  }

  // void setPassword();
  // void changePassword();
  // void encrypt();
  // void decrypt();

private:
  std::vector<std::string> read ();

  std::string filePath_;
  std::string passwordHolder_;

  std::vector<Contact> contacts;
};

} // namespace pbote

#endif // PBOTED_SRC_ADDRESS_BOOK_H_
