/**
 * Copyright (c) 2019-2020 polistern
 */

#ifndef ADDRESS_BOOK_H__
#define ADDRESS_BOOK_H__

#include <string>

#include "Contact.h"

class AddressBook {
 private:
  std::string filePath_;
  std::string passwordHolder_;

 public:
  AddressBook(/* args */);
  ~AddressBook();

  void load() {}

  void save() {}

  void add() {}

  void remove() {}

  void encrypt() {}

  void decrypt() {}
};

AddressBook::AddressBook(/* args */) {}

AddressBook::~AddressBook() {}

#endif // ADDRESS_BOOK_H__
