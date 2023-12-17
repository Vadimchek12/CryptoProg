#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

using namespace std;
using namespace CryptoPP;

void EncryptFile(const string& fileName, const string& password) {
    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string encryptedFile = fileName + ".enc";
    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, key.size(), iv);

    ofstream outputFile(encryptedFile, ios::binary);
    FileSource fs(fileName.c_str(), true, new StreamTransformationFilter(encryption, new FileSink(outputFile)));
}

void DecryptFile(const string& fileName, const string& password) {
    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string decryptedFile = fileName + ".hex";
    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, key.size(), iv);

    ofstream outputFile(decryptedFile, ios::binary);
    FileSource fs(fileName.c_str(), true , new StreamTransformationFilter(decryption, new FileSink(outputFile)));
}

int main() {
    int choice;
    string fileName, password;

    cout << "Выберите режим работы:\n";
    cout << "1. Зашифрование\n";
    cout << "2. Расшифрование\n";
    cin >> choice;

    cout << "Введите имя файла: ";
    cin >> fileName;

    cout << "Введите пароль: ";
    cin >> password;

    switch (choice) {
        case 1:
            EncryptFile(fileName, password);
            cout << "Файл успешно зашифрован.\n";
            break;
        case 2:
            DecryptFile(fileName, password);
            cout << "Файл успешно расшифрован.\n";
            break;
        default:
            cout << "Неверный выбор.\n";
            break;
    }

    return 0;
}
