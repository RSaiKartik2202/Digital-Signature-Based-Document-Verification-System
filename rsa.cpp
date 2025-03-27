#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <cstring>

using namespace std;

// Function to handle errors
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to print the modulus and exponent (e, n) of the public key in hex
void printRSAPublicKey(RSA* rsa) {
    cout << "RSA Public Key (e, n):" << endl;
    
    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    
    // Get modulus (n) and exponent (e)
    RSA_get0_key(rsa, &n, &e, nullptr);

    // Print modulus (n) in hexadecimal
    cout << "n (modulus): ";
    char* n_hex = BN_bn2hex(n);
    cout << n_hex << endl;
    OPENSSL_free(n_hex);

    // Print exponent (e) in hexadecimal
    cout << "e (exponent): ";
    char* e_hex = BN_bn2hex(e);
    cout << e_hex << endl;
    OPENSSL_free(e_hex);
}

// Function to print the modulus and private exponent (d, n) of the private key in hex
void printRSAPrivateKey(RSA* rsa) {
    cout << "RSA Private Key (d, n):" << endl;

    const BIGNUM* n = nullptr;
    const BIGNUM* d = nullptr;

    // Get modulus (n) and private exponent (d)
    RSA_get0_key(rsa, &n, nullptr, &d);

    // Print modulus (n) in hexadecimal
    cout << "n (modulus): ";
    char* n_hex = BN_bn2hex(n);
    cout << n_hex << endl;
    OPENSSL_free(n_hex);

    // Print private exponent (d) in hexadecimal
    cout << "d (private exponent): ";
    char* d_hex = BN_bn2hex(d);
    cout << d_hex << endl;
    OPENSSL_free(d_hex);
}

// Generate RSA keys
void generateRSAKeys(RSA*& rsaPrivateKey, RSA*& rsaPublicKey) {
    // Generate RSA key pair using new method
    BIGNUM* e = BN_new();
    if (!e) handleErrors();

    if (!BN_set_word(e, RSA_F4)) {  // RSA_F4 = 65537 (common public exponent)
        handleErrors();
    }

    // Generate private key
    rsaPrivateKey = RSA_new();
    if (!rsaPrivateKey) handleErrors();

    if (!RSA_generate_key_ex(rsaPrivateKey, 2048, e, nullptr)) {  // 2048 bits key
        handleErrors();
    }

    // Extract the public key from the private key
    rsaPublicKey = RSAPublicKey_dup(rsaPrivateKey);
    if (!rsaPublicKey) {
        handleErrors();
    }

    // Clean up
    BN_free(e);
}

// Encrypt a message using RSA public key
int encryptMessage(RSA* rsaPublicKey, const string& message, unsigned char*& encrypted) {
    int rsaLen = RSA_size(rsaPublicKey);
    encrypted = new unsigned char[rsaLen];

    int result = RSA_public_encrypt(message.length(), reinterpret_cast<const unsigned char*>(message.c_str()), encrypted, rsaPublicKey, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        handleErrors();
    }

    return result;
}

// Decrypt a message using RSA private key
string decryptMessage(RSA* rsaPrivateKey, unsigned char* encryptedMessage, int encryptedLength) {
    int rsaLen = RSA_size(rsaPrivateKey);
    unsigned char* decrypted = new unsigned char[rsaLen];

    int result = RSA_private_decrypt(encryptedLength, encryptedMessage, decrypted, rsaPrivateKey, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        handleErrors();
    }

    string decryptedMessage(reinterpret_cast<char*>(decrypted), result);
    delete[] decrypted;
    return decryptedMessage;
}

int main() {
    // Initialize OpenSSL libraries
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    RSA *rsaPrivateKey = nullptr, *rsaPublicKey = nullptr;
    generateRSAKeys(rsaPrivateKey, rsaPublicKey);

    // Print RSA public and private keys in hexadecimal
    printRSAPublicKey(rsaPublicKey);
    printRSAPrivateKey(rsaPrivateKey);

    string message = "Hello, RSA Encryption!";
    cout << "Original Message: " << message << endl;

    unsigned char* encrypted = nullptr;
    int encryptedLength = encryptMessage(rsaPublicKey, message, encrypted);

    cout << "Encrypted Message: ";
    for (int i = 0; i < encryptedLength; i++) {
        printf("%02x", encrypted[i]);
    }
    cout << endl;

    string decryptedMessage = decryptMessage(rsaPrivateKey, encrypted, encryptedLength);
    cout << "Decrypted Message: " << decryptedMessage << endl;

    // Cleanup
    delete[] encrypted;
    RSA_free(rsaPrivateKey);
    RSA_free(rsaPublicKey);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

