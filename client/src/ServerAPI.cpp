#include "ServerAPI.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QDebug>

ServerAPI::ServerAPI(const std::string& serverUrl, QObject* parent) 
    : QObject(parent), networkManager(new QNetworkAccessManager(this)), serverUrl(serverUrl) {}

void ServerAPI::registerUser(const std::string& phoneNumber, const KeyBundle& initialKeys, ResponseCallback callback) {
    QJsonObject json;
    json["phoneNumber"] = QString::fromStdString(phoneNumber);

    QJsonObject identityKey;
    identityKey["publicKey"] = QString::fromStdString(initialKeys.identityKey);
    // ✅ USE THE CORRECT IDENTITY KEY SIGNATURE FIELD
    identityKey["signature"] = QString::fromStdString(initialKeys.identityKeySignature);
    json["identityKey"] = identityKey;

    QJsonObject signedPrekey;
    signedPrekey["keyId"] = static_cast<qint64>(initialKeys.signedPrekeyId);
    signedPrekey["publicKey"] = QString::fromStdString(initialKeys.signedPrekey);
    signedPrekey["signature"] = QString::fromStdString(initialKeys.signedPrekeySignature);
    json["signedPrekey"] = signedPrekey;
    QJsonArray oneTimePrekeys;
    if (!initialKeys.oneTimePrekey.empty()) {
        QJsonObject otk;
        otk["keyId"] = static_cast<int>(initialKeys.oneTimePrekeyId);
        otk["publicKey"] = QString::fromStdString(initialKeys.oneTimePrekey);
        oneTimePrekeys.append(otk);
    }
    json["oneTimePrekeys"] = oneTimePrekeys;
    
    QJsonDocument doc(json);
    QNetworkReply* reply = postJson("/api/register", doc.toJson().toStdString());
    pendingRequests[reply] = callback;
}

void ServerAPI::verifyPhone(const std::string& phoneNumber, ResponseCallback callback) {
    QJsonObject json;
    json["phoneNumber"] = QString::fromStdString(phoneNumber);
    
    QJsonDocument doc(json);
    QNetworkReply* reply = postJson("/api/verify-phone", doc.toJson().toStdString());
    pendingRequests[reply] = callback;
}

void ServerAPI::fetchKeyBundle(const std::string& phoneNumber, ResponseCallback callback) {
    QJsonObject json;
    json["phoneNumber"] = QString::fromStdString(phoneNumber);
    
    QJsonDocument doc(json);
    QNetworkReply* reply = postJson("/api/keybundle", doc.toJson().toStdString());
    pendingRequests[reply] = callback;
}

void ServerAPI::uploadOneTimePrekeys(const std::string& phoneNumber, const std::vector<std::string>& otks, ResponseCallback callback) {
    QJsonObject json;
    json["phoneNumber"] = QString::fromStdString(phoneNumber);
    
    QJsonArray oneTimePrekeys;
    for (size_t i = 0; i < otks.size(); ++i) {
        QJsonObject otk;
        otk["keyId"] = static_cast<int>(i + 1000); // Generate sequential IDs
        otk["publicKey"] = QString::fromStdString(otks[i]);
        oneTimePrekeys.append(otk);
    }
    json["oneTimePrekeys"] = oneTimePrekeys;
    
    QJsonDocument doc(json);
    QNetworkReply* reply = postJson("/api/upload-otks", doc.toJson().toStdString());
    pendingRequests[reply] = callback;
}

void ServerAPI::rotateSignedPrekey(const std::string& phoneNumber, const std::string& newSignedPrekey, const std::string& signature, ResponseCallback callback) {
    QJsonObject json;
    json["phoneNumber"] = QString::fromStdString(phoneNumber);
    
    QJsonObject signedPrekey;
    signedPrekey["keyId"] = QDateTime::currentSecsSinceEpoch(); // Use timestamp as ID
    signedPrekey["publicKey"] = QString::fromStdString(newSignedPrekey);
    signedPrekey["signature"] = QString::fromStdString(signature);
    json["newSignedPrekey"] = signedPrekey;
    
    QJsonDocument doc(json);
    QNetworkReply* reply = postJson("/api/rotate-signed-prekey", doc.toJson().toStdString());
    pendingRequests[reply] = callback;
}

void ServerAPI::getKeyStats(const std::string& phoneNumber, ResponseCallback callback) {
    QJsonObject json;
    json["phoneNumber"] = QString::fromStdString(phoneNumber);
    
    QJsonDocument doc(json);
    QNetworkReply* reply = postJson("/api/key-stats", doc.toJson().toStdString());
    pendingRequests[reply] = callback;
}

QNetworkReply* ServerAPI::postJson(const std::string& endpoint, const std::string& jsonData) {
    QNetworkRequest request;
    request.setUrl(QUrl(QString::fromStdString(serverUrl + endpoint)));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("User-Agent", "SecureMessaging/2.0");
    
    QNetworkReply* reply = networkManager->post(request, QByteArray::fromStdString(jsonData));
    connect(reply, &QNetworkReply::finished, this, &ServerAPI::onNetworkReply);
    
    return reply;
}

void ServerAPI::onNetworkReply() {
    QNetworkReply* reply = qobject_cast<QNetworkReply*>(sender());
    if (!reply) return;
    
    auto it = pendingRequests.find(reply);
    if (it != pendingRequests.end()) {
        ResponseCallback callback = it->second;
        pendingRequests.erase(it);
        
        if (reply->error() == QNetworkReply::NoError) {
            QByteArray data = reply->readAll();
            callback(true, data.toStdString());
        } else {
            QString errorString = reply->errorString();
            callback(false, errorString.toStdString());
        }
    }
    
    reply->deleteLater();
}
