#ifndef EDHOC_JSON_H
#define EDHOC_JSON_H

#define MAX_FILENAME_SIZE   100
#define FAILURE             (-1)
#define SUCCESS             (0)

/*
 * Structures holding test context information
 */
typedef struct test_edhoc_ctx* test_edhoc_ctx;
typedef struct test_cbor_ctx* test_cbor_ctx;

/*
 * @brief Load an EDHOC test vector from a JSON file
 *
 * @param filename[in]  Filename of the JSON EDHOC test vector
 *
 * @returns Pointer to an initialized test context or NULL
 */
test_edhoc_ctx load_json_edhoc_test_file(const char * filename);

/*
 * @brief Load an CBOR test vector from a JSON file
 *
 * @param filename[in]  Filename of the JSON EDHOC test vector
 *
 * @returns Pointer to an initialized test context or NULL
 */
test_cbor_ctx load_json_cbor_test_file(const char * filename);

/*
 * @brief Close an EDHOC test context (frees all the allocated memory)
 *
 * @param Test context
 */
void close_edhoc_test(test_edhoc_ctx ctx);

/*
 * @brief Close a CBOR test context (frees all the allocated memory)
 *
 * @param Test context
 */
void close_cbor_test(test_cbor_ctx ctx);

/*
 * @brief Load EDHOC data structures from the test vector file
 *
 * @returns 0 on success
 */
int load_from_json_CIPHERSUITE(test_edhoc_ctx ctx, int* value);
int load_from_json_CORR(test_edhoc_ctx ctx, int* value);
int load_from_json_METHOD(test_edhoc_ctx ctx, int* value);
int load_from_json_INIT_CREDTYPE(test_edhoc_ctx ctx, int* value);
int load_from_json_RESP_CREDTYPE(test_edhoc_ctx ctx, int* value);
int load_from_json_INIT_CREDID_TYPE(test_edhoc_ctx ctx, int* value);
int load_from_json_RESP_CREDID_TYPE(test_edhoc_ctx ctx, int* value);

int load_from_json_MESSAGE1(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_MESSAGE2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_MESSAGE3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_DATA2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_DATA3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_TH2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_TH3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_TH4(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_INIT_EPHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_RESP_EPHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_INIT_AUTHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_RESP_AUTHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_DH_SECRET(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_G_X(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_G_Y(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_CONN_IDI(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_CONN_IDR(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_INIT_SALT(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_RESP_SALT(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_PRK2E(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_PRK3E2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_INFO_K2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_INFO_IV2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_K2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_IV2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_K2E(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_P2E(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_M2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_RESP_CRED(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_RESP_CRED_ID(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_INIT_CRED(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_INIT_CRED_ID(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_SIGNATURE(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_CIPHERTEXT2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_CIPHERTEXT3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_CBOR_TEST_NUM(test_cbor_ctx ctx, int *num);
int load_from_json_CBOR_IN(test_cbor_ctx ctx, int num, uint8_t *buf, size_t blen);
int load_from_json_CBOR_OUT(test_cbor_ctx ctx, int num, uint8_t *buf, size_t blen);

#endif /* EDHOC_JSON_H */
