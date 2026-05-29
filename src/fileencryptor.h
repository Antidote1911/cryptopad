#pragma once
#include <QString>
#include <atomic>
#include <functional>

class FileEncryptor {
public:
    static void encryptFile(const QString&                  inputPath,
                             const QString&                  outputPath,
                             const QString&                  password,
                             const std::atomic<bool>&        cancelled,
                             const std::function<void(int)>& progressCb = {});

    static void decryptFile(const QString&                  inputPath,
                             const QString&                  outputPath,
                             const QString&                  password,
                             const std::atomic<bool>&        cancelled,
                             const std::function<void(int)>& progressCb = {});
};
