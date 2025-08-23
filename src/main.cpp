#include <QApplication>
#include <QCommandLineParser>
#include <QMessageBox>
#include <QDir>
#include <QDebug>
#include "MainWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    QCoreApplication::setApplicationName("obSecure");
    QCoreApplication::setApplicationVersion("1.0");
    
    QDir keysDir("keys");
    if (!keysDir.exists()) {
        keysDir.mkpath(".");
    }
    
    QCommandLineParser parser;
    parser.setApplicationDescription("obSecure - Secure messaging application");
    parser.addHelpOption();
    parser.addVersionOption();
    
    parser.addPositionalArgument("username", "Your username for obSecure");
    parser.addPositionalArgument("port", "Port to listen on (optional, default: 8888)", "[port]");
    
    parser.process(app);
    
    const QStringList args = parser.positionalArguments();
    if (args.isEmpty()) {
        qDebug() << "Error: Username is required";
        parser.showHelp(1);
        return 1;
    }
    
    QString userId = args.at(0);
    int port = 8888; 
    
    if (args.size() >= 2) {
        bool ok;
        port = args.at(1).toInt(&ok);
        if (!ok || port < 1024 || port > 65535) {
            qDebug() << "Invalid port:" << args.at(1) << "- using default 8888";
            port = 8888;
        }
    }
    
    qDebug() << "Starting obSecure for user:" << userId << "on port:" << port;
    
    try {
        MainWindow window(userId, port);
        window.show();
        return app.exec();
    } catch (const std::exception& e) {
        QMessageBox::critical(nullptr, "Error", 
                            QString("Failed to start obSecure: %1").arg(e.what()));
        return 1;
    }
}
