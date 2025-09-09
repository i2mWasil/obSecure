#pragma once

#include <string>
#include <vector>
#include <map>

struct Contact {
    std::string userId;
    std::string displayName;
    std::string ipAddress;
    int port;
    bool isOnline;

    Contact() : port(8888), isOnline(false) {}
    Contact(const std::string& id, const std::string& name,
            const std::string& ip, int p = 8888)
        : userId(id), displayName(name), ipAddress(ip), port(p), isOnline(false) {}
};

class UserManager {
private:
    std::string currentUserId;
    std::map<std::string, Contact> contacts;
    std::string contactsFilePath;

public:
    UserManager(const std::string& userId);

    bool addContact(const Contact& contact);
    bool removeContact(const std::string& userId);
    Contact getContact(const std::string& userId) const;
    std::vector<Contact> getAllContacts() const;
    bool hasContact(const std::string& userId) const;
    void updateContactStatus(const std::string& userId, bool isOnline);
    void setCurrentUser(const std::string& userId) { currentUserId = userId; }
    const std::string& getCurrentUserId() const { return currentUserId; }
    bool saveContacts();
    bool loadContacts();

private:
    void ensureContactsDirectory();
};
