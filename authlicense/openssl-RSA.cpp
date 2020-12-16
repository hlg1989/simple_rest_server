#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <assert.h>
#include "openssl-RSA.h"
#include <string.h>

#define RSA_ENCRYPT_BLOCK_SIZE 64

namespace gwecom {
    namespace network{
        namespace rest {

            ssl_key common_ssl_key()
            {
                ssl_key key;
                key.private_key = "-----BEGIN RSA PRIVATE KEY-----\n"
                                  "MIIEowIBAAKCAQEAytjTTKDXui4uszwpbF6ygoTqCp096xEORFe4J7XCIkSdL6EH\n"
                                  "pLG0OGhL5Xd4pV/G8y4M8EwixE5TX9ofxwCYQos72iTyWe3+sNUpSXZFj0rCFjJx\n"
                                  "+wzGC/T/jzBCxwYAlzMQt+sD5nZDdPBgnD/+35F++Rbn17kbPeZtp26hcnN7r86u\n"
                                  "piTTKvBE7zYA9Kvk7QYdjTVP+jt8BFuuJkFDUOjwbmFVDP0NGJcirVMbna0nF+jx\n"
                                  "qIB2abmk4wv4XP9YgTEiOxotemqlXTItZ+slGLhlGv5JXjF/AZSUf/1XJpxxQVmH\n"
                                  "yCkQj41cAhgLkKiC00N1KE2zSbRCbBDg/J2Y9wIDAQABAoIBACXk2ZxgE8zpIbpE\n"
                                  "C+z9x9VQJTS0aUPHnOWxiWqJrumd7ctfBsGCnQtImJ0Wc4hZWx5ExRAC+R+5DiRC\n"
                                  "6FrRxp/vyM+YxVl9d23rdFoP6TC6o4VoCRkAKuNC8pb6Sg9KFMQqOv5QvhrIjxOC\n"
                                  "cFngLqnvUUwRNmB7aRZoPKXhqfFqQlUOoVjoh1OZcww/VYDkYalVMQP9myWKz4BF\n"
                                  "oVIIOc7ABGXeAU2OWUqt1xj3iZEDr+7q8FKw+1Y8Om67CY/m/q4O4HAjw6wOvN8e\n"
                                  "vMg0Op8zi9F+8r5s2KeIt7YgQXAX8QkinFaswuXg/BPih6uXH1gcQGDJtqdDJSIh\n"
                                  "1GCQEYECgYEA5aEvqF3P+XwgbM/xyctGAUvAiaUDYJ1Ckivz+gn+KLBmGem0NV+g\n"
                                  "m2ZaZEo+t60rrN0zOauVg9Y3raYeFFqXUNfbzSsooKknmdcTl9rWXYYgeBYxdEsk\n"
                                  "sRbOGb4M77T6M9pAcKgXWPtxsVK9AGetYCOsW4F47RsnI3o1og53t7cCgYEA4iRD\n"
                                  "g6sCBXHShy+sOgAv3gg23u2OT+avlN2hPDhVLGv9MxwY7oGanMp9cZFsc6b115mv\n"
                                  "cNGAnr5shOdLGdUwAAc6Y9MHXO/9qtxBbBErODSO3xeE9b+w10ba0dnBkzN17dbD\n"
                                  "qdgYYBlZNJwFrYCI/VtaSLK6GtNeC14GLyKUqMECgYAaeKlozF/ET/Xg9VvXOnK4\n"
                                  "hYYNmBM6mQZqmVyHz40YHbW3eQSIPpziLTtwYkq2m+T0CY/1Lv2OdCx4/TRsfkEB\n"
                                  "VdEF5trJIpbpGi0tDVI299ZYYZ6T3HG/ZHSf7RPKsl9BiQByvD3syRfDLFmTaWBI\n"
                                  "O/SLm/JXyxCI+3ahVu+gIwKBgQDeNwI8zPq0fO+CNb9IU0y2Il5A2zBfpXBdmRdK\n"
                                  "BJT1jLwG0BJTs/lJHtT7lwn571NeY7943fVEiBw80McEgG+lZ3TiCMkQcydSERMc\n"
                                  "bRaKKWNHJ2ZY0d+k+xQk55SG4Cd+6e3k5Nq2+9Gjl7kgj9CNHYpvK2ki2RZtlxv+\n"
                                  "jz2DQQKBgFwmc/IETLQ0I4kq7VHySQmA5GQVx8Qa85mvUkCcc9eaUx6v30Aq+I7D\n"
                                  "qKt7tFdSxDvILzBKU9tsfPYYyosZcPVzuWce7EGFLSLLaKJhRiG80ZdnrhGYkZc5\n"
                                  "XCtchCEQNUWafQo7m6Yv1UwEmsubEqSeaaXFUu5FDMfIXbTrkmS8\n"
                                  "-----END RSA PRIVATE KEY-----";

                key.public_key = "-----BEGIN PUBLIC KEY-----\n"
                                 "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAytjTTKDXui4uszwpbF6y\n"
                                 "goTqCp096xEORFe4J7XCIkSdL6EHpLG0OGhL5Xd4pV/G8y4M8EwixE5TX9ofxwCY\n"
                                 "Qos72iTyWe3+sNUpSXZFj0rCFjJx+wzGC/T/jzBCxwYAlzMQt+sD5nZDdPBgnD/+\n"
                                 "35F++Rbn17kbPeZtp26hcnN7r86upiTTKvBE7zYA9Kvk7QYdjTVP+jt8BFuuJkFD\n"
                                 "UOjwbmFVDP0NGJcirVMbna0nF+jxqIB2abmk4wv4XP9YgTEiOxotemqlXTItZ+sl\n"
                                 "GLhlGv5JXjF/AZSUf/1XJpxxQVmHyCkQj41cAhgLkKiC00N1KE2zSbRCbBDg/J2Y\n"
                                 "9wIDAQAB\n"
                                 "-----END PUBLIC KEY-----";

                return key;
            }

            RSA *createPrivateRSA(std::string key) {
                RSA *rsa = NULL;
                const char *c_string = key.c_str();
                BIO *keybio = BIO_new_mem_buf((void *) c_string, -1);
                if (keybio == NULL) {
                    return nullptr;
                }
                rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
                BIO_free(keybio);
                return rsa;
            }

            RSA *createPublicRSA(std::string key) {
                RSA *rsa = NULL;
                BIO *keybio;
                const char *c_string = key.c_str();
                keybio = BIO_new_mem_buf((void *) c_string, -1);
                if (keybio == NULL) {
                    return 0;
                }
                rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
                BIO_free(keybio);
                return rsa;
            }

            bool RSASign(RSA *rsa,
                         const char *Msg,
                         size_t MsgLen,
                         unsigned char **EncMsg,
                         size_t *MsgLenEnc) {
                EVP_MD_CTX *m_RSASignCtx = EVP_MD_CTX_create();
                EVP_PKEY *priKey = EVP_PKEY_new();
                EVP_PKEY_assign_RSA(priKey, rsa);
                if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0) {
                    return false;
                }
                if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
                    return false;
                }
                if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0) {
                    return false;
                }
                *EncMsg = (unsigned char *) malloc(*MsgLenEnc);
                if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
                    return false;
                }
                EVP_MD_CTX_destroy(m_RSASignCtx);
                EVP_PKEY_free(priKey);
                return true;
            }

            bool RSAVerifySignature(RSA *rsa,
                                    unsigned char *MsgHash,
                                    size_t MsgHashLen,
                                    const char *Msg,
                                    size_t MsgLen,
                                    bool *Authentic) {
                *Authentic = false;
                EVP_PKEY *pubKey = EVP_PKEY_new();
                EVP_PKEY_assign_RSA(pubKey, rsa);
                EVP_MD_CTX *m_RSAVerifyCtx = EVP_MD_CTX_create();

                if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0) {
                    EVP_PKEY_free(pubKey);
                    return false;
                }
                if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
                    EVP_PKEY_free(pubKey);
                    return false;
                }
                int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
                if (AuthStatus == 1) {
                    *Authentic = true;
                    EVP_PKEY_free(pubKey);
                    EVP_MD_CTX_destroy(m_RSAVerifyCtx);
                    return true;
                } else if (AuthStatus == 0) {
                    *Authentic = false;
                    EVP_PKEY_free(pubKey);
                    EVP_MD_CTX_destroy(m_RSAVerifyCtx);
                    return true;
                } else {
                    *Authentic = false;
                    EVP_PKEY_free(pubKey);
                    EVP_MD_CTX_destroy(m_RSAVerifyCtx);
                    return false;
                }
            }


            unsigned char *
            signMessage(std::string privateKey, const char *plainSrc, size_t srcLength, size_t encMessageLength) {
                RSA *privateRSA = createPrivateRSA(privateKey);
                if (!privateRSA)
                    return nullptr;
                unsigned char *encMessage;
                RSASign(privateRSA, plainSrc, srcLength, &encMessage, &encMessageLength);
                unsigned char *ret = new unsigned char[encMessageLength];
                memcpy(ret, encMessage, encMessageLength);
                free(encMessage);
                return ret;
            }

            bool verifySignature(std::string publicKey, const char *plainSrc, size_t srcLength,
                                 unsigned char *signatureBase64, size_t size) {
                RSA *publicRSA = createPublicRSA(publicKey);
                if (!publicRSA)
                    return false;
                bool authentic;
                bool result = RSAVerifySignature(publicRSA, signatureBase64, size, plainSrc, srcLength, &authentic);
                return result & authentic;
            }

            rsa_buffer *allocateRSABuffer(std::string key, size_t from_size, RSA_BUFFER_TYPE type) {
                rsa_buffer *ret = nullptr;
                if (from_size <= 0) {
                    return ret;
                }
                switch (type) {
                    case RSA_BUFFER_TYPE_ENCRYPTION: {
                        RSA *publicRSA = createPublicRSA(key);
                        if (!publicRSA)
                            break;
                        size_t rsa_size = RSA_size(publicRSA);
                        RSA_free(publicRSA);
                        int blocks = from_size / RSA_ENCRYPT_BLOCK_SIZE + (from_size % RSA_ENCRYPT_BLOCK_SIZE != 0);
                        ret = new rsa_buffer(blocks * rsa_size);
                    }
                        break;
                    case RSA_BUFFER_TYPE_DECRYPTION: {
                        RSA *privateRSA = createPrivateRSA(key);
                        if (!privateRSA)
                            break;
                        size_t rsa_size = RSA_size(privateRSA);
                        RSA_free(privateRSA);
                        if (from_size % rsa_size != 0) {
                            return nullptr;
                        }

                        ret = new rsa_buffer(from_size);
                    }
                        break;
                    default:
                        break;
                }
                return ret;
            }

            void freeRSABuffer(rsa_buffer *buffer) {
                if (buffer) {
                    if (buffer->data) {
                        delete buffer->data;
                    }
                    delete buffer;
                }

            }

            int encrypt(std::string publicKey, unsigned char *plainSrc, size_t size, unsigned char *result) {
                RSA *publicRSA = createPublicRSA(publicKey);
                int encrypted_length = 0;
                int blocks = size / RSA_ENCRYPT_BLOCK_SIZE + (size % RSA_ENCRYPT_BLOCK_SIZE != 0);
                unsigned char *to = result;
                unsigned char *from = plainSrc;

                for (int i = 0; i < blocks; i++) {
                    size_t src_block_size = RSA_ENCRYPT_BLOCK_SIZE;
                    if (size % RSA_ENCRYPT_BLOCK_SIZE != 0 && i == (blocks - 1)) {
                        src_block_size = size % RSA_ENCRYPT_BLOCK_SIZE;
                    }
                    auto ret = RSA_public_encrypt(src_block_size, from, to, publicRSA, RSA_PKCS1_PADDING);
                    if (ret < 0)
                        return ret;
                    to += RSA_size(publicRSA);
                    from += src_block_size;
                    encrypted_length += ret;
                }
                RSA_free(publicRSA);
                return encrypted_length;

            }

            int decrypt(std::string privateKey, unsigned char *encryptedSrc, size_t size, unsigned char *result) {
                RSA *privateRSA = createPrivateRSA(privateKey);
                if (!privateRSA)
                    return -1;
                size_t rsa_size = RSA_size(privateRSA);
                int decrypted_length = 0;
                unsigned char *from = encryptedSrc;
                unsigned char *to = result;
                int blocks = size / rsa_size;
                if (size % rsa_size != 0) {
                    return -1;
                }
                for (int i = 0; i < blocks; i++) {
                    auto ret = RSA_private_decrypt(rsa_size, from, to, privateRSA, RSA_PKCS1_PADDING);
                    if (ret < 0)
                        return ret;
                    decrypted_length += ret;
                    to += ret;
                    from += rsa_size;
                }
                RSA_free(privateRSA);
                return decrypted_length;
            }


        }
	}
}