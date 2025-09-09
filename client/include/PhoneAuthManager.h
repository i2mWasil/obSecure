#pragma once

#include <string>
#include <memory>
#include <functional>
#include <QObject>
#include "ServerAPI.h"
#include "KeyManager.h"

class PhoneAuthManager : public QObject {
    Q_OBJECT

public:
    using AuthCallback = std::function<void(bool success, const std::string& message)>;
    
private:
    std::shared_ptr<ServerAPI> serverAPI;
    std::shared_ptr<KeyManager> keyManager;

public:
    PhoneAuthManager(std::shared_ptr<ServerAPI> api, std::shared_ptr<KeyManager> keyMgr, QObject* parent = nullptr);
    
    // Authentication flow
    void registerWithServer(AuthCallback callback);
    void fetchContactKeyBundle(const std::string& phoneNumber, std::function<void(bool, const KeyBundle&)> callback);
    void uploadNewOneTimePrekeys(AuthCallback callback);
    void rotateSignedPrekey(AuthCallback callback);
    
    // Utility functions
    static bool validatePhoneNumber(const std::string& phoneNumber);
    static std::string normalizePhoneNumber(const std::string& phoneNumber);

private:
    void generateAndUploadKeys(AuthCallback callback);
};
