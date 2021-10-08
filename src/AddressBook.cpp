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

void AddressBook::load() {

}

void AddressBook::save() {

}

void AddressBook::add() {

}

void AddressBook::remove() {

}

void AddressBook::setPassword() {

}

void AddressBook::changePassword() {

}

void AddressBook::encrypt() {

}

void AddressBook::decrypt() {

}

} // pbote
