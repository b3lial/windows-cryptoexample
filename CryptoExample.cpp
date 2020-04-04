// CryptoExample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <cstdio>

#include <windows.h>
#include <memory.h>
#include <string.h>
#include <wincrypt.h>

using namespace std;

bool encryptData(uint8_t* pCleartext, unsigned int cleartextSize, 
    uint8_t* pEncryptedText, unsigned int encryptedTextSize,
    uint8_t* pPassword, unsigned int passwordLength,
    unsigned int* encryptionResultSize);
bool decryptData(uint8_t* pEncryptedText, unsigned int encryptedTextSize, 
    uint8_t* pCleartext, unsigned int cleartextSize,
    uint8_t* pPassword, unsigned int passwordLength);
bool generateKey(HCRYPTPROV* hProv, HCRYPTPROV* hHash, HCRYPTKEY* hKey,
    uint8_t* pPassword, unsigned int passwordLength);
void freeResources(HCRYPTPROV* hProv, HCRYPTPROV* hHash, HCRYPTKEY* hKey);

int main()
{
    string passwordString = "password123";
    string clearTextString = "I am a string and going to be protected by an awesome encryption algorithm ;)";
    unsigned int encryptionResultSize = 0;

    uint8_t* clearText = new uint8_t[clearTextString.length() + 1];
    unsigned int clearTextBufferSize = clearTextString.length() + 1;
    strcpy_s((char*)clearText, clearTextBufferSize, clearTextString.c_str());

    uint8_t* encryptedText = new uint8_t[clearTextString.length() + 1];
    unsigned int encryptedTextBufferSize = clearTextBufferSize;

    uint8_t* decryptedText = new uint8_t[clearTextString.length() + 1];
    unsigned int decryptedTextBufferSize = clearTextBufferSize;

    bool cryptResult = encryptData(clearText, clearTextBufferSize, encryptedText, encryptedTextBufferSize,
        (uint8_t*) passwordString.c_str(), passwordString.length(), &encryptionResultSize);

    if (!cryptResult){ 
        cerr << "error" << endl;
        delete clearText;
        delete encryptedText;
        delete decryptedText;
        return EXIT_FAILURE; 
    }

    cout << "success, encrypted data size: " << encryptionResultSize << endl;
    bool decryptResult = decryptData(encryptedText, encryptionResultSize,
        decryptedText, decryptedTextBufferSize, (uint8_t*) passwordString.c_str(),
        passwordString.length());

    delete clearText;
    delete encryptedText;
    delete decryptedText;
    return EXIT_SUCCESS; 
}

bool encryptData(uint8_t* pCleartext, unsigned int cleartextSize,
    uint8_t* pEncryptedText, unsigned int encryptedTextSize,
    uint8_t* pPassword, unsigned int passwordLength, 
    unsigned int* encryptionResultSize) {

    HCRYPTPROV hProv;
    HCRYPTPROV hHash;
    HCRYPTKEY hKey;
    DWORD calculatedEncryptionBufferSize = 0;
    DWORD lengthOfPlainText = cleartextSize;

    boolean result = generateKey(&hProv, &hHash, &hKey, pPassword, passwordLength);
    if (!result) {
        return false;
    }

    result = CryptEncrypt(hKey, 0, true, 0, NULL, &calculatedEncryptionBufferSize, 0);
    if (!result) {
        printf("CryptEncrypt() error\n");
        freeResources(&hProv, &hHash, &hKey);
        return false;
    }
    if (calculatedEncryptionBufferSize > encryptedTextSize) {
        printf("Encryption buffer size == %d but we need %d bytes\n",
            encryptedTextSize, calculatedEncryptionBufferSize);
        freeResources(&hProv, &hHash, &hKey);
        return false;
    }

    if (pCleartext != pEncryptedText) {
        memcpy_s(pEncryptedText, encryptedTextSize, pCleartext, cleartextSize);
    }

    result = CryptEncrypt(hKey, 0, true, 0, pEncryptedText, &lengthOfPlainText, encryptedTextSize);
    if (!result) {
        printf("CryptEncrypt() error\n");
    }
    else {
        *encryptionResultSize = lengthOfPlainText;
    }
    freeResources(&hProv, &hHash, &hKey);
    return result;
}

bool decryptData(uint8_t* pEncryptedText, unsigned int encryptedTextSize,
    uint8_t* pCleartext, unsigned int clearTextSize,
    uint8_t* pPassword, unsigned int passwordLength) {

    HCRYPTPROV hProv;
    HCRYPTPROV hHash;
    HCRYPTKEY hKey;
    DWORD dataLen = encryptedTextSize;

    bool result = generateKey(&hProv, &hHash, &hKey, pPassword, passwordLength);
    if (!result) {
        return false;
    }

    if (pCleartext != pEncryptedText) {
        memcpy_s(pCleartext, clearTextSize, pEncryptedText, encryptedTextSize);
    }
    if (dataLen > clearTextSize) {
        dataLen = clearTextSize;
        printf("warning, seems decrypted data will be truncated\n");
    }

    result = CryptDecrypt(hKey, 0, true, 0, pCleartext, &dataLen);
    if (!result) {
        printf("CryptDecrypt() error\n");
    }

    freeResources(&hProv, &hHash, &hKey);
    return result;
}

bool generateKey(HCRYPTPROV* hProv, HCRYPTPROV* hHash, HCRYPTKEY* hKey,
    uint8_t* pPassword, unsigned int passwordLength) {
    bool result = CryptAcquireContext(hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (!result) {
        printf("CryptAcquireContext() error\n");
        goto exit_generatekey;
    }

    result = CryptCreateHash(*hProv, CALG_MD5, 0, 0, hHash);
    if (!result) {
        printf("CryptCreateHash() error\n");
        goto exit_prov;
    }

    result = CryptHashData(*hHash, (BYTE*)pPassword, passwordLength, 0);
    if (!result) {
        printf("CryptHashData() error\n");
        goto exit_hash;
    }

    result = CryptDeriveKey(*hProv, CALG_RC4, *hHash, 0, hKey);
    if (!result) {
        printf("CryptDeriveKey() error\n");
        goto exit_hash;
    }
    return true;

exit_hash:
    CryptDestroyHash(*hHash);
exit_prov:
    CryptReleaseContext(*hProv, 0);
exit_generatekey:
    return false;
}

void freeResources(HCRYPTPROV* hProv, HCRYPTPROV* hHash, HCRYPTKEY* hKey) {
    CryptDestroyKey(*hKey);
    CryptDestroyHash(*hHash);
    CryptReleaseContext(*hProv, 0);
}