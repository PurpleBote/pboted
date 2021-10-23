/**
 * Copyright (c) 2019-2021 polistern
 */

#include <utility>

#include "AddressBook.h"

namespace pbote {

AddressBook::AddressBook() {}

AddressBook::AddressBook(std::string path, std::string pass)
    : filePath_(std::move(path)), passwordHolder_(std::move(pass)) {}

AddressBook::~AddressBook() {}

void AddressBook::load() {}

void AddressBook::save() {}

void AddressBook::add(std::string &name, std::string &address) {
  addresses.insert(std::pair<std::string, std::string>(name, address));
}

bool AddressBook::exist(const std::string &name) {
  return addresses.find(name) != addresses.end();
}

std::string AddressBook::get_address(const std::string &name) {
  if (exist(name))
    return addresses.find(name)->second;
  return {};
}

void AddressBook::remove(const std::string &name) {
  addresses.erase(name);
}

void AddressBook::setPassword() {}

void AddressBook::changePassword() {}

void AddressBook::encrypt() {}

void AddressBook::decrypt() {}

} // namespace pbote
