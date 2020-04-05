# windows-cryptoexample
An example which demonstrates how to encrypt/decrypt data using the Windows crypto API.
Methods check input/output array sizes and may fail if not enough space is available. I am using this in a C++ example but the core functions are plain C.

* **encryptData()**: encrypts an array and writes the size of the encrypted data to *encryptionResultSize*. Returns *true* on success, otherwise *false*.
* **decryptData()**: decrypts an array with a given key. Returns *true* on success, otherwise *false*.
