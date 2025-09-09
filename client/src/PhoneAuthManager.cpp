#include "PhoneAuthManager.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <regex>
#include <iostream>

PhoneAuthManager::PhoneAuthManager(std::shared_ptr<ServerAPI> api, std::shared_ptr<KeyManager> keyMgr, QObject* parent)
    : QObject(parent), serverAPI(api), keyManager(keyMgr) {}

void PhoneAuthManager::registerWithServer(AuthCallback callback) {
    try {
        // Get current key bundle
        KeyBundle bundle = keyManager->getCurrentKeyBundle();
        
        serverAPI->registerUser(keyManager->getPhoneNumber(), bundle, 
            [callback](bool success, const std::string& response) {
                if (success) {
                    std::cout << "Registration successful: " << response << std::endl;
                    callback(true, "Registration successful");
                } else {
                    std::cout << "Registration failed: " << response << std::endl;
                    callback(false, "Registration failed: " + response);
                }
            });
    } catch (const std::exception& e) {
        callback(false, "Registration error: " + std::string(e.what()));
    }
}

void PhoneAuthManager::fetchContactKeyBundle(const std::string& phoneNumber, std::function<void(bool, const KeyBundle&)> callback) {
    serverAPI->fetchKeyBundle(phoneNumber, 
        [callback](bool success, const std::string& response) {
            if (success) {
                try {
                    // Parse JSON response
                    QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(response));
                    QJsonObject obj = doc.object();
                    
                    KeyBundle bundle;
                    
                    // Parse identity key
                    QJsonObject identityKey = obj["identityKey"].toObject();
                    bundle.identityKey = identityKey["publicKey"].toString().toStdString();
                    
                    // Parse signed prekey
                    QJsonObject signedPrekey = obj["signedPrekey"].toObject();
                    bundle.signedPrekey = signedPrekey["publicKey"].toString().toStdString();
                    bundle.signedPrekeySignature = signedPrekey["signature"].toString().toStdString();
                    bundle.signedPrekeyId = signedPrekey["keyId"].toInt();
                    
                    // Parse one-time prekey (optional)
                    if (obj.contains("oneTimePrekey")) {
                        QJsonObject oneTimePrekey = obj["oneTimePrekey"].toObject();
                        bundle.oneTimePrekey = oneTimePrekey["publicKey"].toString().toStdString();
                        bundle.oneTimePrekeyId = oneTimePrekey["keyId"].toInt();
                    }
                    
                    callback(true, bundle);
                } catch (const std::exception& e) {
                    KeyBundle emptyBundle;
                    callback(false, emptyBundle);
                }
            } else {
                KeyBundle emptyBundle;
                callback(false, emptyBundle);
            }
        });
}

void PhoneAuthManager::uploadNewOneTimePrekeys(AuthCallback callback) {
    try {
        // Generate new one-time prekeys
        keyManager->generateOneTimePrekeys(50);
        keyManager->saveKeys();
        
        // Get public keys
        std::vector<std::string> publicKeys = keyManager->getOneTimePrekeyPublics();
        
        serverAPI->uploadOneTimePrekeys(keyManager->getPhoneNumber(), publicKeys,
            [callback](bool success, const std::string& response) {
                if (success) {
                    callback(true, "One-time prekeys uploaded successfully");
                } else {
                    callback(false, "Failed to upload one-time prekeys: " + response);
                }
            });
    } catch (const std::exception& e) {
        callback(false, "Error generating one-time prekeys: " + std::string(e.what()));
    }
}

void PhoneAuthManager::rotateSignedPrekey(AuthCallback callback) {
    try {
        // Generate new signed prekey
        keyManager->rotateSignedPrekey();
        keyManager->saveKeys();
        
        // Get new signed prekey bundle
        KeyBundle bundle = keyManager->getCurrentKeyBundle();
        
        serverAPI->rotateSignedPrekey(keyManager->getPhoneNumber(), 
                                    bundle.signedPrekey, 
                                    bundle.signedPrekeySignature,
            [callback](bool success, const std::string& response) {
                if (success) {
                    callback(true, "Signed prekey rotated successfully");
                } else {
                    callback(false, "Failed to rotate signed prekey: " + response);
                }
            });
    } catch (const std::exception& e) {
        callback(false, "Error rotating signed prekey: " + std::string(e.what()));
    }
}

bool PhoneAuthManager::validatePhoneNumber(const std::string& phoneNumber) {
    // Basic E.164 format validation
    std::regex phoneRegex(R"(^\+[1-9]\d{1,14}$)");
    return std::regex_match(phoneNumber, phoneRegex);
}

std::string PhoneAuthManager::normalizePhoneNumber(const std::string& phoneNumber) {
    // Remove all non-digit characters except +
    std::string cleaned;
    for (char c : phoneNumber) {
        if (std::isdigit(c) || c == '+') {
            cleaned += c;
        }
    }
    
    // Ensure it starts with +
    if (!cleaned.empty() && cleaned[0] != '+') {
        cleaned = "+" + cleaned;
    }
    
    return cleaned;
}
