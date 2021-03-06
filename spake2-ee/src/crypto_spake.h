
#ifndef crypto_spake_H
#define crypto_spake_H 1

//#define crypto_spake_DUMMYKEYBYTES    32
//#define crypto_spake_PUBLICDATABYTES  36
//#define crypto_spake_RESPONSE1BYTES   32
//#define crypto_spake_RESPONSE2BYTES   64
//#define crypto_spake_RESPONSE3BYTES   32
//#define crypto_spake_SHAREDKEYBYTES   32
//#define crypto_spake_STOREDBYTES     164

typedef struct crypto_spake_shared_keys_ {
    unsigned char client_sk[32];
    unsigned char server_sk[32];
} crypto_spake_shared_keys;

typedef struct crypto_spake_client_state_ {
    unsigned char h_K[32];
    unsigned char h_L[32];
    unsigned char N[32];
    unsigned char x[32];
    unsigned char X[32];
} crypto_spake_client_state;

typedef struct crypto_spake_server_state_ {
    unsigned char server_validator[32];
    crypto_spake_shared_keys shared_keys;
} crypto_spake_server_state;

int crypto_spake_server_store(unsigned char stored_data[164],
                              const char * const salt,
                              const char * const passwd, unsigned long long passwdlen,
                              unsigned long long opslimit, size_t memlimit);

int crypto_spake_validate_public_data(const unsigned char public_data[36],
                                      const int expected_alg,
                                      unsigned long long expected_opslimit,
                                      unsigned long long expected_memlimit);

int crypto_spake_step0_dummy(crypto_spake_server_state *st,
                             unsigned char public_data[36],
                             const char *client_id, size_t client_id_len,
                             const char *server_id, size_t server_id_len,
                             unsigned long long opslimit, size_t memlimit,
                             const unsigned char key[32]);

int crypto_spake_step0(crypto_spake_server_state *st,
                       unsigned char public_data[36],
                       const unsigned char stored_data[164]);

int crypto_spake_step1(crypto_spake_client_state *st, unsigned char response1[32],
                       const unsigned char public_data[36],
                       const char * const passwd, unsigned long long passwdlen);

int crypto_spake_step2(crypto_spake_server_state *st,
                       unsigned char response2[64],
                       const char *client_id, size_t client_id_len,
                       const char *server_id, size_t server_id_len,
                       const unsigned char stored_data[164],
                       const unsigned char response1[32]);

int crypto_spake_step3(crypto_spake_client_state *st,
                       unsigned char response3[32],
                       crypto_spake_shared_keys *shared_keys,
                       const char *client_id, size_t client_id_len,
                       const char *server_id, size_t server_id_len,
                       const unsigned char response2[64]);

int crypto_spake_step4(crypto_spake_server_state *st,
                       crypto_spake_shared_keys *shared_keys,
                       const unsigned char response3[32]);

#endif
