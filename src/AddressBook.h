/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef ADDRESS_BOOK_H__
#define ADDRESS_BOOK_H__

#include <map>
#include <string>
#include <vector>

namespace pbote {

struct Contact {
public:
  Contact() = default;

  std::string alias{};
  std::string name{};
  std::string dest{};
};

class AddressBook {
public:
  AddressBook();
  AddressBook(std::string path, std::string pass);
  ~AddressBook();

  void load();
  void save();

  void add(std::string &alias, std::string &name, std::string &address);
  bool name_exist(const std::string &name);
  bool alias_exist(const std::string &alias);
  std::string address_for_name(const std::string &name);
  std::string address_for_alias(const std::string &alias);
  void remove(const std::string &name);

  size_t size() { return contacts.size(); }

  //void setPassword();
  //void changePassword();
  //void encrypt();
  //void decrypt();

private:
  std::vector<std::string> read();

  std::string filePath_;
  std::string passwordHolder_;

  std::vector<Contact> contacts;
};

} // namespace pbote

#endif // ADDRESS_BOOK_H__
