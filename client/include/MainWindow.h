#pragma once

#include <QMainWindow>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QTextEdit>
#include <QLineEdit>
#include <QDialog>
#include <QFormLayout>
#include <QSpinBox>
#include <QDialogButtonBox>
#include <memory>
#include <set>
#include <map>
#include <chrono>
#include "KeyManager.h"
#include "CryptoManager.h"
#include "NetworkManager.h"
#include "UserManager.h"
#include "X3DHManager.h"
#include "PhoneAuthManager.h"
#include "ServerAPI.h"
#include "MessageProtocol.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

private:
    // UI Components
    QWidget* centralWidget;
    QHBoxLayout* mainLayout;
    QVBoxLayout* leftLayout;
    QVBoxLayout* rightLayout;

    // Left panel - Contacts
    QLabel* contactsLabel;
    QListWidget* contactsList;
    QPushButton* addContactButton;
    QPushButton* deleteContactButton;
    QPushButton* connectButton;
    QPushButton* disconnectButton;
    QPushButton* sharePublicKeyButton;
    QPushButton* refreshKeysButton;
    QLabel* statusLabel;

    // Right panel - Chat
    QLabel* chatLabel;
    QTextEdit* messageDisplay;
    QHBoxLayout* inputLayout;
    QLineEdit* messageInput;
    QPushButton* sendButton;

    // Core managers
    std::shared_ptr<KeyManager> keyManager;
    std::unique_ptr<CryptoManager> cryptoManager;
    std::unique_ptr<NetworkManager> networkManager;
    std::unique_ptr<UserManager> userManager;
    std::shared_ptr<ServerAPI> serverAPI;
    std::unique_ptr<PhoneAuthManager> phoneAuthManager;
    std::unique_ptr<X3DHManager> x3dhManager;

    // Session management
    std::set<QString> activeSessions;
    std::map<QString, std::string> sessionKeys;
    std::map<QString, uint32_t> messageCounters;

    // Current state
    QString currentPhoneNumber;
    QString currentChatUser;
    int serverPort;

public:
    MainWindow(const QString& phoneNumber, int port = 8888, QWidget* parent = nullptr);
    ~MainWindow();

private slots:
    void onSendMessage();
    void onMessageReceived(const EncryptedMessage& message);
    void onX3DHMessageReceived(const X3DHMessage& x3dhMessage);
    void onContactSelected();
    void onAddContact();
    void onDeleteContact();
    void onConnectToUser();
    void onDisconnectFromUser();
    void onUserConnected(const QString& userId);
    void onUserDisconnected(const QString& userId);
    void onConnectionError(const QString& error);
    void onSharePublicKey();
    void onRefreshKeys();

private:
    void setupUI();
    void initializeManagers();
    void displayMessage(const QString& sender, const QString& message, bool isOutgoing = false);
    void updateContactsList();
    void updateStatusLabel();
    void updateButtonStates();
    QString getCurrentTime();

    // Session management
    bool hasActiveSession(const QString& phoneNumber);
    void setActiveSession(const QString& phoneNumber, bool active);
    std::string getSessionKey(const QString& phoneNumber);
    void setSessionKey(const QString& phoneNumber, const std::string& key);
    uint32_t getMessageCounter(const QString& phoneNumber);
    void incrementMessageCounter(const QString& phoneNumber);
    uint64_t getCurrentTimestamp();
};
