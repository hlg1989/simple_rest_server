#pragma once
#include <string>
namespace gwecom {
    namespace network{
        namespace rest {

            typedef struct ssl_key{
                std::string private_key;
                std::string public_key;
            }ssl_key;

            enum RSA_BUFFER_TYPE {
                RSA_BUFFER_TYPE_ENCRYPTION,
                RSA_BUFFER_TYPE_DECRYPTION
            };

            typedef struct rsa_buffer {
                int size;
                unsigned char *data;

                rsa_buffer(int size) : size(size), data(new unsigned char[size]) {};
            } rsa_buffer;

            ssl_key common_ssl_key();

            unsigned char *
            signMessage(std::string privateKey, const char *plainSrc, size_t srcLength, size_t encMessageLength);

            bool verifySignature(std::string publicKey, const char *plainSrc, size_t srcLength,
                                 unsigned char *signatureBase64, size_t size);

            /*  Allocates buffer for rsa encrypt or decrypt.
                Parameters:
                    key: public key for encrytion; private for decryption.
            */
            rsa_buffer *allocateRSABuffer(std::string key, size_t from_size, RSA_BUFFER_TYPE type);

            void freeRSABuffer(rsa_buffer *buffer);

            int encrypt(std::string publicKey, unsigned char *plainSrc, size_t size, unsigned char *result);

            int decrypt(std::string privateKey, unsigned char *encryptedSrc, size_t size, unsigned char *result);

        }
	}
}
