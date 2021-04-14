#ifndef EDHOC_JSON_H
#define EDHOC_JSON_H

#define MAX_FILENAME_SIZE   100
#define FAILURE             (-1)
#define SUCCESS             (0)

/*
 * Structures holding test context information
 */
typedef struct test_edhoc_ctx* test_edhoc_ctx;
typedef struct test_cred_ctx* test_cred_ctx;

/*
 * @brief Load an EDHOC test vector from a JSON file
 *
 * @param filename[in]  Filename of the JSON EDHOC test vector
 *
 * @returns Pointer to an initialized test context or NULL
 */
test_edhoc_ctx load_json_edhoc_test_file(const char *filename);

/*
 * @brief Load an CBOR test vector from a JSON file
 *
 * @param filename[in]  Filename of the JSON EDHOC test vector
 *
 * @returns Pointer to an initialized test context or NULL
 */
test_cred_ctx load_json_cred_test_file(const char *filename);

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
void close_cred_test(test_cred_ctx ctx);

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

int load_from_json_INPUT_TH2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_TH2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_INPUT_TH3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_TH3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_INPUT_TH4(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_TH4(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_INIT_EPHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_RESP_EPHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_INIT_AUTHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_RESP_AUTHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_DH_SECRET(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_G_X(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_G_Y(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_I(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_R(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_G_I(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_G_R(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_CONN_IDI(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_CONN_IDR(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_PRK2E(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_PRK3E2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_PRK4X3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_INFO_K2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_INFO_K3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_INFO_IV2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_INFO_IV3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_K2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_K3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_IV2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_IV3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_INFO_KEYSTREAM(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_KEYSTREAM(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_A3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_A2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_P2E(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_M2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_M3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_RESP_CRED(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_RESP_CRED_ID(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_INIT_CRED(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_INIT_CRED_ID(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_SIGNATURE2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_SIGNATURE3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_CIPHERTEXT2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_MAC2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_MAC3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_CIPHERTEXT3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_CBORCERT(test_cred_ctx ctx, uint8_t* buf, size_t blen);
int load_from_json_CBORCERT_TYPE(test_cred_ctx ctx, int *value);
int load_from_json_CBORCERT_SERIALNUMBER(test_cred_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_CBORCERT_ISSUER(test_cred_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_CBORCERT_SUBJECT(test_cred_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_CBORCERT_SUBJECTPKA(test_cred_ctx ctx, int *value);
int load_from_json_CBORCERT_SUBJECTPK(test_cred_ctx ctx, uint8_t *buf, size_t blen);
int load_from_json_CBORCERT_ISSUERALGORITHM(test_cred_ctx ctx, int *value);
int load_from_json_CBORCERT_SIGNATURE(test_cred_ctx ctx, uint8_t *buf, size_t blen);

int load_from_json_RPK(test_cred_ctx ctx, uint8_t* buf, size_t blen);
int load_from_json_RPK_CURVE(test_cred_ctx ctx, int* value);
int load_from_json_RPK_X(test_cred_ctx ctx, uint8_t* buf, size_t blen);
int load_from_json_RPK_D(test_cred_ctx ctx, uint8_t* buf, size_t blen);

int load_from_json_INFO_OSCORE_SECRET(test_edhoc_ctx ctx, uint8_t* buf, size_t blen);
int load_from_json_INFO_OSCORE_SALT(test_edhoc_ctx ctx, uint8_t* buf, size_t blen);
int load_from_json_OSCORE_SECRET(test_edhoc_ctx ctx, uint8_t* buf, size_t blen);
int load_from_json_OSCORE_SALT(test_edhoc_ctx ctx, uint8_t* buf, size_t blen);

#endif /* EDHOC_JSON_H */
