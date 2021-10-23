/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef ADDRESS_BOOK_H__
#define ADDRESS_BOOK_H__

#include <map>
#include <string>

namespace pbote {

class AddressBook {
public:
  AddressBook();
  AddressBook(std::string path, std::string pass);
  ~AddressBook();

  void load();
  void save();

  void add(std::string &name, std::string &address);
  bool exist(const std::string &name);
  std::string get_address(const std::string &name);
  void remove(const std::string &name);

  void setPassword();
  void changePassword();
  void encrypt();
  void decrypt();

private:
  std::string filePath_;
  std::string passwordHolder_;

  std::map<std::string, std::string> addresses;
};

} // namespace pbote

#endif // ADDRESS_BOOK_H__
