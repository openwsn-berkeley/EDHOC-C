#ifndef EDHOC_JSON_H
#define EDHOC_JSON_H

#define MAX_FILENAME_SIZE   100
#define FAILURE             (-1)
#define SUCCESS             (0)

/*
 * Structure holding test context information
 */
typedef struct test_context* test_context_ptr;

/*
 * @brief Load a test vector from a JSON file
 *
 * @param filename[in]  Filename of the JSON test vector
 *
 * @returns Pointer to an initialized test context or NULL
 */
test_context_ptr load_json_test_file(const char * filename);

/*
 * @brief Close a test context (frees all the allocated memory)
 *
 * @param Test context
 */
void close_test(test_context_ptr ctx);

/*
 * @brief Load EDHOC data structures from the test vector file
 *
 * @returns 0 on success
 */
int load_from_json_CIPHERSUITE(test_context_ptr ctx, int* value);
int load_from_json_CORR(test_context_ptr ctx, int* value);
int load_from_json_METHOD(test_context_ptr ctx, int* value);

int load_from_json_MESSAGE1(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_MESSAGE2(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_MESSAGE3(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_DATA2(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_DATA3(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_TH2(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_TH3(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_TH4(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_INIT_EPHKEY(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_RESP_EPHKEY(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_INIT_AUTHKEY(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_RESP_AUTHKEY(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_DH_SECRET(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_G_X(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_G_Y(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_CONN_IDI(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_CONN_IDR(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_INIT_SALT(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_RESP_SALT(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_PRK2E(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_PRK3E2M(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_INFO_K2M(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_INFO_IV2M(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_K2M(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_IV2M(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_K2E(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_P2E(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_M2(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_RESP_CRED(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_RESP_CRED_ID(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_INIT_CRED(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_INIT_CRED_ID(test_context_ptr ctx, uint8_t *buf, size_t blen);

int load_from_json_SIGNATURE(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_CIPHERTEXT2(test_context_ptr ctx, uint8_t *buf, size_t blen);
int load_from_json_CIPHERTEXT3(test_context_ptr ctx, uint8_t *buf, size_t blen);



#endif /* EDHOC_JSON_H */
