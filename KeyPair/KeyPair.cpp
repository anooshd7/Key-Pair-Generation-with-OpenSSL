#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

bool generateKeyPair(std::string& publicKey, std::string& privateKey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr); //key algorithm context
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_keygen_init(ctx);     //Generates key with context

    EVP_PKEY_keygen(ctx, &pkey);

    //Memory BIOs 
    BIO* bioPrivateKey = BIO_new(BIO_s_mem());
    BIO* bioPublicKey = BIO_new(BIO_s_mem());

    //Write keys to BIOs
    PEM_write_bio_PrivateKey(bioPrivateKey, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    PEM_write_bio_PUBKEY(bioPublicKey, pkey);

    //Get keys from BIOs and store in string
    char* privateKeyData;
    long privateKeySize = BIO_get_mem_data(bioPrivateKey, &privateKeyData);
    privateKey.assign(privateKeyData, privateKeySize);

    char* publicKeyData;
    long publicKeySize = BIO_get_mem_data(bioPublicKey, &publicKeyData);
    publicKey.assign(publicKeyData, publicKeySize);

    BIO_free_all(bioPublicKey);
    BIO_free_all(bioPrivateKey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return true;
} 

// signal protocol

bool saveToFile(const std::string& filename, const std::string& data, bool isPEMFormat) {
    std::ofstream file(filename, std::ios::binary);
    if (isPEMFormat) {
        
        file << data;
    }
    
    file.close();
    return true;
}

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::string Base64Encode(const unsigned char* secretData, size_t length) {
    std::string encoded_data;

    encoded_data.reserve(((length + 2) / 3) * 4);
    // std::cout << length << std::endl;

    // Iterate over each group of 3 bytes
    for (size_t i = 0; i < length; i += 3) {
        unsigned char byte1 = secretData[i];
        unsigned char byte2 = (i + 1 < length) ? secretData[i + 1] : 0;
        unsigned char byte3 = (i + 2 < length) ? secretData[i + 2] : 0;

        // Encode the 3 bytes into 4 base64 characters
        unsigned char b64char1 = byte1 >> 2;
        unsigned char b64char2 = ((byte1 & 0x03) << 4) | (byte2 >> 4);
        unsigned char b64char3 = ((byte2 & 0x0F) << 2) | (byte3 >> 6);
        unsigned char b64char4 = byte3 & 0x3F;

        encoded_data += base64_chars[b64char1];
        encoded_data += base64_chars[b64char2];
        encoded_data += (i + 1 < length) ? base64_chars[b64char3] : '=';
        encoded_data += (i + 2 < length) ? base64_chars[b64char4] : '=';

        // pushback function

        
    }
    
    return encoded_data;
}

unsigned char* Base64Decode(const std::string& encoded_data , int length) {
    unsigned char* decoded_data = new unsigned char [length];

    int j = 0;

    // Iterate over each group of 4 characters
    for (size_t i = 0; i < encoded_data.length(); i += 4) {
        unsigned char b64char1 = base64_chars.find(encoded_data[i]);
        unsigned char b64char2 = base64_chars.find(encoded_data[i + 1]);
        unsigned char b64char3 = (encoded_data[i + 2] != '=') ? base64_chars.find(encoded_data[i + 2]) : 0;
        unsigned char b64char4 = (encoded_data[i + 3] != '=') ? base64_chars.find(encoded_data[i + 3]) : 0;

        // Decode the 4 base64 characters into 3 bytes
        unsigned char byte1 = (b64char1 << 2) | (b64char2 >> 4);
        unsigned char byte2 = ((b64char2 & 0x0F) << 4) | (b64char3 >> 2);
        unsigned char byte3 = ((b64char3 & 0x03) << 6) | b64char4;

        decoded_data[j] = byte1;
        
        

        if (encoded_data[i + 2] != '=')
            decoded_data[j+1] = byte2;

        if (encoded_data[i + 3] != '=')
            decoded_data[j+2] = byte3;

        j += 3;
    }

    return decoded_data; 

}

std:: string generateSharedSecret(const std::string& publicKey, const std::string& privateKey) {

    // Load public key from PEM format
    BIO* bioPublicKey = BIO_new_mem_buf(publicKey.data(), publicKey.size());
    EVP_PKEY* peerPublicKey = PEM_read_bio_PUBKEY(bioPublicKey, nullptr, nullptr, nullptr);
    BIO_free(bioPublicKey);

    // Load private key from PEM format
    BIO* bioPrivateKey = BIO_new_mem_buf(privateKey.data(), privateKey.size());
    EVP_PKEY* ownPrivateKey = PEM_read_bio_PrivateKey(bioPrivateKey, nullptr, nullptr, nullptr);
    BIO_free(bioPrivateKey);

    // Diffie-Hellman context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ownPrivateKey, nullptr);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peerPublicKey);

    // size of the shared secret
    size_t secretSize;
    EVP_PKEY_derive(ctx, nullptr, &secretSize);

    // Generate the shared secret 
    unsigned char* secretData = new unsigned char[secretSize];
    EVP_PKEY_derive(ctx, secretData, &secretSize); //derives shared secret using context

    // Clean up
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerPublicKey);
    EVP_PKEY_free(ownPrivateKey);
    
    //return secretData;

    std::string encoded_data = Base64Encode(secretData, secretSize);
    std::cout << encoded_data << std::endl;

    return encoded_data;
    
}


std::pair<std::string, int> encryptString(const std::string& plainText, const unsigned char* aes_key, int keyLength) {
    std::string encryptedText;

    // Generate an initialization vector(IV)
    unsigned char iv[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv, EVP_MAX_IV_LENGTH);

    // Create the encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);

    // Set padding mode
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    // Get the cipher block size
    int blockSize = EVP_CIPHER_CTX_block_size(ctx);

    // Calculate the required output buffer size
    int encryptedTextLength = plainText.length() + blockSize;
    unsigned char* encryptedTextBuffer = new unsigned char[encryptedTextLength];

    // Encrypt the plain text
    int finalLength = 0;
    EVP_EncryptUpdate(ctx, encryptedTextBuffer, &encryptedTextLength, (const unsigned char*)plainText.c_str(), plainText.length());
    finalLength += encryptedTextLength;
    EVP_EncryptFinal_ex(ctx, encryptedTextBuffer + encryptedTextLength, &encryptedTextLength);
    finalLength += encryptedTextLength;

    // Combine IV and cipher text
    encryptedText.append(reinterpret_cast<char*>(iv), EVP_MAX_IV_LENGTH);
    encryptedText.append(reinterpret_cast<char*>(encryptedTextBuffer), finalLength);

    //Base64Encode(encryptedTextBuffer)

    // Clean up
    delete[] encryptedTextBuffer;
    EVP_CIPHER_CTX_free(ctx);

    return std::make_pair(encryptedText, finalLength);
    
}

std::string decryptString(const std::string& encryptedText, const unsigned char* aes_key, int length) {
    std::string decryptedText;

    // Extract the IV and cipher text
    const unsigned char* iv = reinterpret_cast<const unsigned char*>(encryptedText.c_str());
    const unsigned char* cipherText = iv + EVP_MAX_IV_LENGTH;
    //int cipherTextLength = encryptedText.length() - EVP_MAX_IV_LENGTH;

    // Create the decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);

    // Set padding mode
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    // Get the cipher block size
    int blockSize = EVP_CIPHER_CTX_block_size(ctx);

    // Calculate the required output buffer size
    int decryptedTextLength = length + blockSize;
    unsigned char* decryptedTextBuffer = new unsigned char[decryptedTextLength];

    // Decrypt the cipher text
    int finalLength = 0;
    EVP_DecryptUpdate(ctx, decryptedTextBuffer, &decryptedTextLength, cipherText, length);
    finalLength += decryptedTextLength;
    EVP_DecryptFinal_ex(ctx, decryptedTextBuffer + decryptedTextLength, &decryptedTextLength);
    finalLength += decryptedTextLength;

    // Remove any padding bytes
    if (finalLength > 0) {
        int paddingLength = decryptedTextBuffer[finalLength - 1];
        if (paddingLength > 0 && paddingLength <= blockSize) {
            finalLength -= paddingLength;
        }
    }

    // Set the decrypted text
    decryptedText.assign(reinterpret_cast<char*>(decryptedTextBuffer), finalLength);

    // Clean up
    delete[] decryptedTextBuffer;
    EVP_CIPHER_CTX_free(ctx);

    return decryptedText;
}
 
int main() {
    std::string bobPublicKey, bobPrivateKey, alicePublicKey, alicePrivateKey;
    std::string plainText = "Hello World";

    // Generates key pair for Bob
    if (generateKeyPair(bobPublicKey, bobPrivateKey)) {
        if (saveToFile("bob_public_key.pem", bobPublicKey, true) && saveToFile("bob_private_key.pem", bobPrivateKey, true)) {
            std::cout << "Bob's keys saved successfully." << std::endl;
        }
    }

    // Generates key pair for Alice
    if (generateKeyPair(alicePublicKey, alicePrivateKey)) {
        if (saveToFile("alice_public_key.pem", alicePublicKey, true) && saveToFile("alice_private_key.pem", alicePrivateKey, true)) {
            std::cout << "Alice's keys saved successfully." << std::endl;
        }
    }



    // Alice's shared secret
    //unsigned char* alice = generateSharedSecret(bobPublicKey, alicePrivateKey);
    //size_t len = strlen((char*)alice); 
    std::string aliceSharedSecret = generateSharedSecret(bobPublicKey, alicePrivateKey);
    if (saveToFile("alice_shared_secret.txt", aliceSharedSecret, true)) {
        std::cout << "Alice's shared secret key saved successfully." << std::endl;
    }


    // Bob's shared secret
    std::string bobSharedSecret = generateSharedSecret(alicePublicKey, bobPrivateKey);
    if (saveToFile("bob_shared_secret.txt", aliceSharedSecret, true)) {
        std::cout << "Bob's shared secret key saved successfully." << std::endl;
    }

    // Compare the shared secret keys
    if (bobSharedSecret == aliceSharedSecret) {

        const unsigned char* aes_key = Base64Decode(aliceSharedSecret, 32);
        int keyLength = 32;
        
        std::pair< std::string, int> string = encryptString(plainText, aes_key, keyLength);
        std::string decryptedText = decryptString(string.first, aes_key, string.second);

        std::cout << "Plain text: " << plainText << std::endl;
        std::cout << "Encrypted text: " << string.first << std::endl;
        std::cout << "Decrypted text: " << decryptedText << std::endl;


        return 0;
    }

}
