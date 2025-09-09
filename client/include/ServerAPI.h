#pragma once

#include <string>
#include <functional>
#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include "MessageProtocol.h"

class ServerAPI : public QObject {
    Q_OBJECT

public:
    using ResponseCallback = std::function<void(bool success, const std::string& response)>;
    
private:
    QNetworkAccessManager* networkManager;
    std::string serverUrl;
    std::string userPhone;

public:
    ServerAPI(const std::string& serverUrl, QObject* parent = nullptr);
    
    // User registration and authentication
    void registerUser(const std::string& phoneNumber, const KeyBundle& initialKeys, ResponseCallback callback);
    void verifyPhone(const std::string& phoneNumber, ResponseCallback callback);
    
    // Key management
    void fetchKeyBundle(const std::string& phoneNumber, ResponseCallback callback);
    void uploadOneTimePrekeys(const std::string& phoneNumber, const std::vector<std::string>& otks, ResponseCallback callback);
    void rotateSignedPrekey(const std::string& phoneNumber, const std::string& newSignedPrekey, const std::string& signature, ResponseCallback callback);
    void getKeyStats(const std::string& phoneNumber, ResponseCallback callback);

private slots:
    void onNetworkReply();

private:
    std::string makeJsonRequest(const std::string& endpoint, const std::string& jsonData);
    QNetworkReply* postJson(const std::string& endpoint, const std::string& jsonData);
    
    std::map<QNetworkReply*, ResponseCallback> pendingRequests;
};
