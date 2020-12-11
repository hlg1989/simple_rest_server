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
                                 "MIIEpAIBAAKCAQEAyPDoDMnCOut9Z/kDWScXWsRYh+jbRSUUpwvEAE5tNoqfdoRR\n"
                                 "ZIc53DMGy87PgHRfSmhKlAuSkpYyH7QiEthvOx4cqxXy35TPUIpvPehWmeqc2xd+\n"
                                 "VaoMbZO/wsM10AHVVHEUZbkEWEI/PWVf2aZ4tv2qZ8d2yY66bk9W5wO9ry/nXWKS\n"
                                 "6f9GQionAFDiHQCpdrxjtzIwfbSBdLFAvrFkVu2QfGhzExztAbDRNadx2dkgCE0Q\n"
                                 "6kZmJl1UlOpJGuPZCygKnypNSwZ9QjPR8/LwnCWKUFRIrTVaiWoa4sUDZ1DXCZ0S\n"
                                 "iyM4Bo509zL0kJq2WvX/92ZUdCrUFYC6mrjcxwIDAQABAoIBAQC+9svhU2Emc6ST\n"
                                 "ykBXWuJEHbNxPmgcd1gARRs5m08JdYaEsM1Vd3oSfd/okxv6nR3ubdzqg3EBpIHw\n"
                                 "RVXYiR50lXJzWYGe4CKCDX4Y3JRo5GG7icFDkj8LaE3mv3SFwShHfsv+vG2XnyXQ\n"
                                 "qGYGR8ITTlHDHPoUJXOh3/7bv19me7XDbHpCgACizdwOEMscFt7ZsumQ3ZEURsw4\n"
                                 "eajDXQLdHEUJZkDFqUUw36q6gV2ctZjVWieBbvxmR/gr+exK3jE7U7nEppre+2QK\n"
                                 "EHNA5f31SpmfKsTz/3mapBrl4nJhDX0/uhR10wEaf7uF1Pa8rXRJiL0adVedWJeC\n"
                                 "VRaN0Gb5AoGBAOuJca8gaiHWXOm/4XiPgm5TCnpjpImSQk4D6QSxYq6zfyT0Ckvq\n"
                                 "XTCYyHjJAlkdKdEO4kzeCt6Mx5NbqRQ60m+je7Crm75eo2UlcxUnTMcoNEKsGbcY\n"
                                 "0uBHqH6M5C9eIYbRgjyKQu7wP/7qfp++zUiQmd/HNFsxoBa6wQoMd5nFAoGBANpm\n"
                                 "BN30fiQArYRLPu9gGW5UnL4REsFSFH8+wrrdty73Ak+kSaRasVSAZfxWUUmoPUy3\n"
                                 "y+/zhx04jnDUwhlz0FZnuQXfz0GEL8CxdeFDqTRA5ykk7p1Oo8y0TXGppOZBMSD8\n"
                                 "tcaky8FHETr3XbJiE4eZUfM/9uilwklVjQsa+GEbAoGAalO8l1MptibAAOGXFkaq\n"
                                 "mcUw+LkcoOH+vpszSOQO6VCsd/EW6Nhewz5lWWlcfwAUTYTLkem2vGqO+a2qMTCw\n"
                                 "qKcDgmilwRWV62Yxgn4gQdOba/GnFinFoGuY27Acnml+9w6DHXNI7fZU3W3cRZ7r\n"
                                 "qvNkE0opD3XikAA0fqXMJAUCgYAF9w9e+JSRaytSF7QKWbeYGduGHXVDrng82Xv8\n"
                                 "Gp4sPDbl8fjI8mkxg6hFch4aQuwZslNxpFcmZysMzeLXSyB/m6mkDW7dvTyIqNAt\n"
                                 "bOmsMbGeoBGcXk9/AdWzqwyD9XfgDMbyPAIMr2I7GBKJEsCxzXA9kput0wkxc5K8\n"
                                 "oOnzzQKBgQDczBh6eZnyEJ05/R+PdEHbgNdxnt8QCTVsowcAjNs71BVvKKYV+DBr\n"
                                 "zJH5ZcvUHc2Isxn0wp0qATjky12AkRDpk+UTdOj/9Edn2ymEShAW3u3YbvxtQh8D\n"
                                 "iRwzQ5dtXxx+xehGeidvz/wav4fEHYDyaLL9NcFXMtCIGqsLXuOyog==\n"
                                 "-----END RSA PRIVATE KEY-----";

                key.public_key = "-----BEGIN PUBLIC KEY-----\n"
                                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyPDoDMnCOut9Z/kDWScX\n"
                                "WsRYh+jbRSUUpwvEAE5tNoqfdoRRZIc53DMGy87PgHRfSmhKlAuSkpYyH7QiEthv\n"
                                "Ox4cqxXy35TPUIpvPehWmeqc2xd+VaoMbZO/wsM10AHVVHEUZbkEWEI/PWVf2aZ4\n"
                                "tv2qZ8d2yY66bk9W5wO9ry/nXWKS6f9GQionAFDiHQCpdrxjtzIwfbSBdLFAvrFk\n"
                                "Vu2QfGhzExztAbDRNadx2dkgCE0Q6kZmJl1UlOpJGuPZCygKnypNSwZ9QjPR8/Lw\n"
                                "nCWKUFRIrTVaiWoa4sUDZ1DXCZ0SiyM4Bo509zL0kJq2WvX/92ZUdCrUFYC6mrjc\n"
                                "xwIDAQAB\n"
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