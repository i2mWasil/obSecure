#ifndef NETWORKMANAGER_H
#define NETWORKMANAGER_H

#include <QTcpServer>
#include <QTcpSocket>
#include <QObject>
#include <QTimer>
#include <map>
#include <vector>
#include "MessageProtocol.h"

class NetworkManager : public QObject {
    Q_OBJECT

private:
    QTcpServer* server;
    std::map<QString, QTcpSocket*> activeConnections;
    std::map<QTcpSocket*, QString> socketToUserId;
    int serverPort;
    QString currentUserId;

public:
    NetworkManager(const QString& userId, int port = 8888, QObject* parent = nullptr);
    ~NetworkManager();
    
    bool startServer();
    void stopServer();
    bool sendMessage(const QString& receiverId, const EncryptedMessage& message);
    bool connectToUser(const QString& userId, const QString& address, int port);
    void disconnectFromUser(const QString& userId);
    
    bool isConnectedToUser(const QString& userId) const;
    std::vector<QString> getConnectedUsers() const;

signals:
    void messageReceived(const EncryptedMessage& message);
    void userConnected(const QString& userId);
    void userDisconnected(const QString& userId);
    void connectionError(const QString& error);

private slots:
    void onNewConnection();
    void onDataReceived();
    void onClientDisconnected();
    void onConnectionError(QAbstractSocket::SocketError error);

private:
    void processIncomingData(QTcpSocket* socket, const QByteArray& data);
    void handleHandshake(QTcpSocket* socket, const MessageProtocol& message);
    void sendHandshake(QTcpSocket* socket);
    void cleanupConnection(QTcpSocket* socket);
};

#endif 
