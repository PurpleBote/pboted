/**
 * Copyright (c) 2019-2021 polistern
 */

#ifndef ADDRESS_BOOK_H__
#define ADDRESS_BOOK_H__

#include <string>

//#include "Contact.h"

namespace pbote {

class AddressBook {
 public:
  AddressBook();
  AddressBook(std::string path, std::string pass);
  ~AddressBook();

  void load();
  void save();

  void add();
  void remove();

  void setPassword();
  void changePassword();
  void encrypt();
  void decrypt();

 private:
  std::string filePath_;
  std::string passwordHolder_;
};

} // pbote

#endif // ADDRESS_BOOK_H__
