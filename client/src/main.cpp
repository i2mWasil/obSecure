#include <QApplication>
#include <QCommandLineParser>
#include <QMessageBox>
#include <QDir>
#include <QInputDialog>
#include <QDebug>
#include "MainWindow.h"
#include "PhoneAuthManager.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    QCoreApplication::setApplicationName("obSecure");
    QCoreApplication::setApplicationVersion("2.0");
    
    // Ensure keys directory exists
    QDir keysDir("keys");
    if (!keysDir.exists()) {
        keysDir.mkpath(".");
    }
    
    QCommandLineParser parser;
    parser.setApplicationDescription("Secure Messaging - End-to-end encrypted messaging with X3DH");
    parser.addHelpOption();
    parser.addVersionOption();
    
    parser.addPositionalArgument("port", "Port to listen on (optional, default: 8888)", "[port]");
    parser.process(app);
    
    // Get mobile number from user
    bool ok;
    QString phoneNumber = QInputDialog::getText(nullptr, 
        "Phone Number", 
        "Enter your mobile number with country code (e.g., +1234567890):",
        QLineEdit::Normal, "", &ok);
    
    if (!ok || phoneNumber.isEmpty()) {
        qDebug() << "Phone number is required";
        return 1;
    }
    
    // Validate phone number format
    if (!PhoneAuthManager::validatePhoneNumber(phoneNumber.toStdString())) {
        QMessageBox::critical(nullptr, "Invalid Phone Number", 
                            "Please enter a valid phone number with country code (e.g., +1234567890)");
        return 1;
    }
    
    // Normalize phone number
    std::string normalizedPhone = PhoneAuthManager::normalizePhoneNumber(phoneNumber.toStdString());
    
    const QStringList args = parser.positionalArguments();
    int port = 8888;
    
    if (!args.isEmpty()) {
        port = args.at(0).toInt(&ok);
        if (!ok || port < 1024 || port > 65535) {
            qDebug() << "Invalid port, using default 8888";
            port = 8888;
        }
    }
    
    qDebug() << "Starting Secure Messaging for:" << QString::fromStdString(normalizedPhone) << "on port:" << port;
    
    try {
        MainWindow window(QString::fromStdString(normalizedPhone), port);
        window.show();
        return app.exec();
    } catch (const std::exception& e) {
        QMessageBox::critical(nullptr, "Error", 
                            QString("Failed to start application: %1").arg(e.what()));
        return 1;
    }
}
//make -j$(sysctl -n hw.ncpu)