#pragma once
#include <QtWidgets>
#include <memory>
#include "KeyManager.h"
#include "CryptoManager.h"
#include "NetworkManager.h"
#include "UserManager.h"

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
    QLabel* statusLabel;
    
    // Right panel - Chat
    QLabel* chatLabel;
    QTextEdit* messageDisplay;
    QHBoxLayout* inputLayout;
    QLineEdit* messageInput;
    QPushButton* sendButton;
    
    // Core managers
    std::unique_ptr<KeyManager> keyManager;
    std::unique_ptr<CryptoManager> cryptoManager;
    std::unique_ptr<NetworkManager> networkManager;
    std::unique_ptr<UserManager> userManager;
    
    QString currentUserId;
    QString currentChatUser;
    int serverPort; 

public:
    MainWindow(const QString& userId, int port = 8888, QWidget* parent = nullptr);  
    ~MainWindow();

private slots:
    void onSendMessage();
    void onMessageReceived(const EncryptedMessage& message);
    void onContactSelected();
    void onAddContact();
    void onDeleteContact();
    void onConnectToUser();
    void onDisconnectFromUser();
    void onUserConnected(const QString& userId);
    void onUserDisconnected(const QString& userId);
    void onConnectionError(const QString& error);
    void onSharePublicKey();

private:
    void setupUI();
    void initializeManagers();
    void displayMessage(const QString& sender, const QString& message, bool isOutgoing = false);
    void updateContactsList();
    void updateStatusLabel();
    void updateButtonStates();
    QString getCurrentTime();
};
