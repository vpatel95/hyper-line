#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

typedef struct encrypt_s {
    unsigned char   aeskey[32];
    unsigned char   aesiv[32];
    unsigned char   aesPass[32];
    unsigned char   aesSalt[32];
    char            data[1048];
} encrypt_t;

int32_t encryption_init (FILE *in, FILE *op, int32_t offset) {
    int32_t     i = 0, rc = 0;
    size_t      len, data_len;
    char        *line = NULL;
    encrypt_t   aes_obj;

    if (in == NULL || op == NULL) {
        return EXIT_FAILURE;
    }

    fseek(in, offset, SEEK_SET);

    while (i < 10000) {
        rc = getline(&line, &len, in);
        if (rc < 0) {
            fflush(op);
            return 0;
        }

        snprintf(aes_obj.data, len+1, "%s", line);

        if (0 == RAND_bytes(aes_obj.aeskey, sizeof(aes_obj.aeskey))) goto bail;
        if (0 == RAND_bytes(aes_obj.aesiv, sizeof(aes_obj.aesiv))) goto bail;
        if (0 == RAND_bytes(aes_obj.aesPass, sizeof(aes_obj.aesPass))) goto bail;
        if (0 == RAND_bytes(aes_obj.aesSalt, sizeof(aes_obj.aesSalt))) goto bail;

        data_len = sizeof(aes_obj);

        fwrite(&data_len, sizeof(size_t), 1, op);
        fwrite(&aes_obj, sizeof(aes_obj), 1, op);
        i++;
    }

    fflush(op);
    return (int32_t)(ftell(in));

bail:
    return EXIT_FAILURE;
}

int32_t aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *data,
                           unsigned char *ctext, int len) {
  int32_t flen = 0;
  int32_t clen = len + AES_BLOCK_SIZE;

  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_EncryptUpdate(e, ctext, &clen, data, len);
  EVP_EncryptFinal_ex(e, ctext + clen, &flen);

  len = clen + flen;

  return len;
}


int32_t aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ctext,
                    unsigned char *ptext, int len) {
    int plen = len, flen = 0;

    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, ptext, &plen, ctext, len);
    EVP_DecryptFinal_ex(e, ptext + plen, &flen);

    len = plen + flen;
    return len;

}

int32_t encrypt (FILE *in, FILE *op, int32_t offset) {
    (void)(offset);
    int32_t         rc = 0;
    int32_t         rounds = 50;
    int32_t         data_len;
    size_t          len;
    encrypt_t       aes_obj;
    EVP_CIPHER_CTX  *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX  *de = EVP_CIPHER_CTX_new();

    if (in == NULL || op == NULL) {
        return EXIT_FAILURE;
    }

    while (0 < (rc = fread(&len, sizeof(size_t), 1, in))) {
        unsigned char ciphertext[2048];
        unsigned char plaintext[2048];
        if (0 == (rc = fread(&aes_obj, len, 1, in))) {
            return EXIT_FAILURE;
        }

        rc = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), aes_obj.aesSalt,
                            aes_obj.aesPass, sizeof(aes_obj.aesPass), rounds,
                            aes_obj.aeskey, aes_obj.aesiv);

        if (32 != rc) {
            goto bail;
        }

        data_len = strlen(aes_obj.data) + 1;

        EVP_CIPHER_CTX_init(en);
        EVP_EncryptInit_ex(en, EVP_aes_256_cbc(), NULL, aes_obj.aeskey, aes_obj.aesiv);

        data_len = aes_encrypt(en, (unsigned char *)aes_obj.data, ciphertext, data_len);

        fprintf(op, "%s\n", ciphertext);

        EVP_CIPHER_CTX_init(de);
        EVP_DecryptInit_ex(de, EVP_aes_256_cbc(), NULL, aes_obj.aeskey, aes_obj.aesiv);

        data_len = aes_decrypt(de, ciphertext, plaintext, data_len);
        printf("%s", plaintext);
    }
    fflush(op);

    return 0;

bail:
    return EXIT_FAILURE;
}
