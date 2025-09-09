#include "UserManager.h"
#include <QDir>
#include <iostream>
#include <fstream>
#include <sstream>

UserManager::UserManager(const std::string& userId) : currentUserId(userId) {
    contactsFilePath = "keys/" + userId + "/contacts.json";
    ensureContactsDirectory();
    loadContacts();
}

void UserManager::ensureContactsDirectory() {
    QDir dir;
    dir.mkpath(QString::fromStdString("keys/" + currentUserId));
}

bool UserManager::addContact(const Contact& contact) {
    if (contact.userId == currentUserId) {
        return false; // Can't add self as contact
    }

    contacts[contact.userId] = contact;
    return saveContacts();
}

bool UserManager::removeContact(const std::string& userId) {
    auto it = contacts.find(userId);
    if (it != contacts.end()) {
        contacts.erase(it);
        return saveContacts();
    }
    return false;
}

Contact UserManager::getContact(const std::string& userId) const {
    auto it = contacts.find(userId);
    if (it != contacts.end()) {
        return it->second;
    }
    throw std::runtime_error("Contact not found: " + userId);
}

std::vector<Contact> UserManager::getAllContacts() const {
    std::vector<Contact> result;
    for (const auto& pair : contacts) {
        result.push_back(pair.second);
    }
    return result;
}

bool UserManager::hasContact(const std::string& userId) const {
    return contacts.find(userId) != contacts.end();
}

void UserManager::updateContactStatus(const std::string& userId, bool isOnline) {
    auto it = contacts.find(userId);
    if (it != contacts.end()) {
        it->second.isOnline = isOnline;
        saveContacts();
    }
}

bool UserManager::saveContacts() {
    try {
        std::ofstream file(contactsFilePath);
        if (!file.is_open()) {
            std::cerr << "Failed to open contacts file for writing: " << contactsFilePath << std::endl;
            return false;
        }

        for (const auto& pair : contacts) {
            const Contact& contact = pair.second;
            file << contact.userId << "|"
                 << contact.displayName << "|"
                 << contact.ipAddress << "|"
                 << contact.port << "|"
                 << (contact.isOnline ? "1" : "0") << "\n";
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving contacts: " << e.what() << std::endl;
        return false;
    }
}

bool UserManager::loadContacts() {
    try {
        std::ifstream file(contactsFilePath);
        if (!file.is_open()) {
            return true; // File doesn't exist yet, that's okay
        }

        std::string line;
        while (std::getline(file, line)) {
            if (line.empty()) continue;

            std::istringstream iss(line);
            std::string token;
            Contact contact;

            if (std::getline(iss, token, '|')) contact.userId = token;
            if (std::getline(iss, token, '|')) contact.displayName = token;
            if (std::getline(iss, token, '|')) contact.ipAddress = token;
            if (std::getline(iss, token, '|')) contact.port = std::stoi(token);
            if (std::getline(iss, token, '|')) contact.isOnline = (token == "1");

            if (!contact.userId.empty()) {
                contacts[contact.userId] = contact;
            }
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading contacts: " << e.what() << std::endl;
        return false;
    }
}
