#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <cjson/cJSON.h>

#include "json.h"

struct test_cbor_ctx {
    char *filename;
    unsigned long json_size;
    char *json_buffer;
    const cJSON *root;
};

struct test_edhoc_ctx {
    char *filename;
    unsigned long json_size;
    char *json_buffer;
    const cJSON *root;
    const cJSON *initiator;
    const cJSON *responder;
    const cJSON *shared;
};

test_cbor_ctx load_json_cbor_test_file(const char *filename) {
    unsigned long read_size;
    unsigned long name_len;
    test_cbor_ctx ctx;
    FILE *fp;

    if ((ctx = malloc(sizeof(struct test_cbor_ctx))) == NULL) {
        return NULL;
    }

    // clear test_context
    memset(ctx, 0, sizeof(struct test_cbor_ctx));

    if ((name_len = strnlen(filename, MAX_FILENAME_SIZE)) == MAX_FILENAME_SIZE) {
        // file name size too big
        return NULL;
    } else {
        ctx->filename = malloc(sizeof(char) * (name_len + 1));
        memcpy(ctx->filename, filename, name_len);
        ctx->filename[name_len] = '\0';
    }

    if ((fp = fopen(filename, "r")) == NULL) {
        free(ctx->filename);
        ctx->filename = NULL;

        free(ctx);

        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    ctx->json_size = ftell(fp);
    rewind(fp);

    ctx->json_buffer = (char *) malloc(sizeof(char) * (ctx->json_size + 1));
    read_size = fread(ctx->json_buffer, sizeof(char), ctx->json_size, fp);

    ctx->json_buffer[ctx->json_size] = '\0';

    // close file
    fclose(fp);

    if (ctx->json_size != read_size) {

        close_cbor_test(ctx);

        return NULL;
    }

    // start JSON parsing
    ctx->root = cJSON_Parse(ctx->json_buffer);

    if (!cJSON_IsObject(ctx->root)) {
        close_cbor_test(ctx);

        return NULL;
    }

    return ctx;
}

test_edhoc_ctx load_json_edhoc_test_file(const char *filename) {
    unsigned long read_size;
    unsigned long name_len;
    test_edhoc_ctx ctx;
    FILE *fp;

    if ((ctx = malloc(sizeof(struct test_edhoc_ctx))) == NULL) {
        return NULL;
    }

    // clear test_context
    memset(ctx, 0, sizeof(struct test_edhoc_ctx));

    if ((name_len = strnlen(filename, MAX_FILENAME_SIZE)) == MAX_FILENAME_SIZE) {
        // file name size too big
        return NULL;
    } else {
        ctx->filename = malloc(sizeof(char) * (name_len + 1));
        memcpy(ctx->filename, filename, name_len);
        ctx->filename[name_len] = '\0';
    }

    if ((fp = fopen(filename, "r")) == NULL) {
        free(ctx->filename);
        ctx->filename = NULL;

        free(ctx);

        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    ctx->json_size = ftell(fp);
    rewind(fp);

    ctx->json_buffer = (char *) malloc(sizeof(char) * (ctx->json_size + 1));
    read_size = fread(ctx->json_buffer, sizeof(char), ctx->json_size, fp);

    ctx->json_buffer[ctx->json_size] = '\0';

    // close file
    fclose(fp);

    if (ctx->json_size != read_size) {

        close_edhoc_test(ctx);

        return NULL;
    }

    // start JSON parsing
    ctx->root = cJSON_Parse(ctx->json_buffer);

    if (!cJSON_IsObject(ctx->root)) {
        close_edhoc_test(ctx);

        return NULL;
    }

    if ((ctx->initiator = cJSON_GetObjectItemCaseSensitive(ctx->root, "I")) == NULL) {
        close_edhoc_test(ctx);
        return NULL;
    }

    if ((ctx->responder = cJSON_GetObjectItemCaseSensitive(ctx->root, "R")) == NULL) {
        close_edhoc_test(ctx);
        return NULL;
    }

    if ((ctx->shared = cJSON_GetObjectItemCaseSensitive(ctx->root, "S")) == NULL) {
        close_edhoc_test(ctx);
        return NULL;
    }

    return ctx;
}

void close_edhoc_test(test_edhoc_ctx ctx) {

    cJSON_Delete((cJSON *) ctx->root);

    // free filename
    free(ctx->filename);
    ctx->filename = NULL;

    // free json buffer
    free(ctx->json_buffer);
    ctx->json_buffer = NULL;

    // free context itself
    free(ctx);
}

void close_cbor_test(test_cbor_ctx ctx) {

    cJSON_Delete((cJSON *) ctx->root);

    // free filename
    free(ctx->filename);
    ctx->filename = NULL;

    // free json buffer
    free(ctx->json_buffer);
    ctx->json_buffer = NULL;

    // free context itself
    free(ctx);
}

static size_t load_json_hexString(cJSON *string, uint8_t *buf, size_t blen) {
    const char *hex_string;
    const char *pos;
    size_t i, hex_len;

    if (!cJSON_IsString(string)) {
        return FAILURE;
    }

    hex_string = cJSON_GetStringValue(string);
    hex_len = strlen(hex_string) / 2;
    pos = hex_string;

    if (hex_len > blen || strlen(hex_string) % 2 != 0) {
        return FAILURE;
    }

    for (i = 0; i <= hex_len; i++) {
        sscanf(pos, "%2hhx", &buf[i]);
        pos += 2;
    }

    return hex_len;
}

int load_from_json_MESSAGE1(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *message1;

    if ((message1 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "message_1")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(message1, buf, blen);
}

int load_from_json_SIGNATURE(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *signature;

    if ((signature = cJSON_GetObjectItemCaseSensitive(ctx->shared, "signature_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(signature, buf, blen);
}

int load_from_json_M2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *m_2;

    if ((m_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "m_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(m_2, buf, blen);
}

int load_from_json_MESSAGE2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *message2;

    if ((message2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "message_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(message2, buf, blen);
}

int load_from_json_MESSAGE3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *message3;

    if ((message3 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "message_3")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(message3, buf, blen);
}

int load_from_json_DATA2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *data_2;

    if ((data_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "data_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(data_2, buf, blen);
}

int load_from_json_INIT_SALT(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *salt;

    if ((salt = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "salt")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(salt, buf, blen);
}

int load_from_json_RESP_SALT(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *salt;

    if ((salt = cJSON_GetObjectItemCaseSensitive(ctx->responder, "salt")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(salt, buf, blen);
}

int load_from_json_PRK2E(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *prk2e;

    if ((prk2e = cJSON_GetObjectItemCaseSensitive(ctx->shared, "prk2e")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(prk2e, buf, blen);
}

int load_from_json_PRK3E2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *prk3e2m;

    if ((prk3e2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "prk3e2m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(prk3e2m, buf, blen);
}

int load_from_json_K2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *k2m;

    if ((k2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "k2m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(k2m, buf, blen);
}

int load_from_json_INFO_K2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *info_k2m;

    if ((info_k2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "info_k2m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(info_k2m, buf, blen);
}

int load_from_json_IV2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *iv2m;

    if ((iv2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "iv2m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(iv2m, buf, blen);
}

int load_from_json_RESP_CRED(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *cred;

    if ((cred = cJSON_GetObjectItemCaseSensitive(ctx->responder, "cred")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(cred, buf, blen);
}

int load_from_json_INIT_CRED(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *cred;

    if ((cred = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "cred")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(cred, buf, blen);
}

int load_from_json_RESP_CRED_ID(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *cred_id;

    if ((cred_id = cJSON_GetObjectItemCaseSensitive(ctx->responder, "cred_id")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(cred_id, buf, blen);
}

int load_from_json_INIT_CRED_ID(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *cred_id;

    if ((cred_id = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "cred_id")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(cred_id, buf, blen);
}

int load_from_json_INFO_IV2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *info_iv2m;

    if ((info_iv2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "info_iv2m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(info_iv2m, buf, blen);
}

int load_from_json_TH2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *th_2;

    if ((th_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "th_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(th_2, buf, blen);
}

int load_from_json_K2E(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *k_2e;

    if ((k_2e = cJSON_GetObjectItemCaseSensitive(ctx->shared, "k_2e")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(k_2e, buf, blen);
}

int load_from_json_P2E(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *p_2e;

    if ((p_2e = cJSON_GetObjectItemCaseSensitive(ctx->shared, "p_2e")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(p_2e, buf, blen);
}

int load_from_json_CIPHERTEXT2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *ciphertext_2;

    if ((ciphertext_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "ciphertext_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(ciphertext_2, buf, blen);
}

int load_from_json_CIPHERTEXT3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *ciphertext_3;

    if ((ciphertext_3 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "ciphertext_3")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(ciphertext_3, buf, blen);
}

int load_from_json_INIT_EPHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *eph_key;

    if ((eph_key = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "eph_key")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(eph_key, buf, blen);
}

int load_from_json_INIT_AUTHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *auth_key;

    if ((auth_key = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "auth_key")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(auth_key, buf, blen);
}

int load_from_json_RESP_AUTHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *auth_key;

    if ((auth_key = cJSON_GetObjectItemCaseSensitive(ctx->responder, "auth_key")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(auth_key, buf, blen);
}

int load_from_json_RESP_EPHKEY(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *eph_key;

    if ((eph_key = cJSON_GetObjectItemCaseSensitive(ctx->responder, "eph_key")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(eph_key, buf, blen);
}

int load_from_json_DH_SECRET(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *secret;

    if ((secret = cJSON_GetObjectItemCaseSensitive(ctx->shared, "secret")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(secret, buf, blen);
}

int load_from_json_G_X(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *g_x;

    if ((g_x = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "g_x")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(g_x, buf, blen);
}

int load_from_json_G_Y(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *g_y;

    if ((g_y = cJSON_GetObjectItemCaseSensitive(ctx->responder, "g_y")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(g_y, buf, blen);
}

int load_from_json_CONN_IDI(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *conn_id;

    if ((conn_id = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "conn_id")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(conn_id, buf, blen);
}

int load_from_json_CONN_IDR(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *conn_id;

    if ((conn_id = cJSON_GetObjectItemCaseSensitive(ctx->responder, "conn_id")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(conn_id, buf, blen);
}

int load_from_json_CORR(test_edhoc_ctx ctx, int *value) {
    cJSON *correlation;

    if (!cJSON_IsObject(ctx->initiator)) {
        return FAILURE;
    }

    if ((correlation = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "correlation")) == NULL) {
        return FAILURE;
    }

    *value = correlation->valueint;

    return SUCCESS;
}

int load_from_json_METHOD(test_edhoc_ctx ctx, int *value) {
    cJSON *method;

    if (!cJSON_IsObject(ctx->initiator)) {
        return FAILURE;
    }

    if ((method = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "method")) == NULL) {
        return FAILURE;
    }

    *value = method->valueint;

    return SUCCESS;
}

int load_from_json_INIT_CREDTYPE(test_edhoc_ctx ctx, int *value) {
    cJSON *cred_type;

    if (!cJSON_IsObject(ctx->initiator)) {
        return FAILURE;
    }

    if ((cred_type = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "cred_type")) == NULL) {
        return FAILURE;
    }

    *value = cred_type->valueint;

    return SUCCESS;
}

int load_from_json_INIT_CREDID_TYPE(test_edhoc_ctx ctx, int *value) {
    cJSON *cred_id_type;

    if (!cJSON_IsObject(ctx->initiator)) {
        return FAILURE;
    }

    if ((cred_id_type = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "cred_id_type")) == NULL) {
        return FAILURE;
    }

    *value = cred_id_type->valueint;

    return SUCCESS;
}

int load_from_json_RESP_CREDID_TYPE(test_edhoc_ctx ctx, int *value) {
    cJSON *cred_id_type;

    if (!cJSON_IsObject(ctx->responder)) {
        return FAILURE;
    }

    if ((cred_id_type = cJSON_GetObjectItemCaseSensitive(ctx->responder, "cred_id_type")) == NULL) {
        return FAILURE;
    }

    *value = cred_id_type->valueint;

    return SUCCESS;
}

int load_from_json_RESP_CREDTYPE(test_edhoc_ctx ctx, int *value) {
    cJSON *cred_type;

    if (!cJSON_IsObject(ctx->responder)) {
        return FAILURE;
    }

    if ((cred_type = cJSON_GetObjectItemCaseSensitive(ctx->responder, "cred_type")) == NULL) {
        return FAILURE;
    }

    *value = cred_type->valueint;

    return SUCCESS;
}

int load_from_json_CIPHERSUITE(test_edhoc_ctx ctx, int *value) {
    cJSON *selected;

    if (!cJSON_IsObject(ctx->initiator)) {
        return FAILURE;
    }

    if ((selected = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "selected")) == NULL) {
        return FAILURE;
    }

    *value = selected->valueint;

    return SUCCESS;
}

int load_from_json_CBOR_TEST_NUM(test_cbor_ctx ctx, int *num) {
    cJSON *number_of_tests;

    if (!cJSON_IsObject(ctx->root)) {
        return FAILURE;
    }

    if ((number_of_tests = cJSON_GetObjectItemCaseSensitive(ctx->root, "tests")) == NULL) {
        return FAILURE;
    }

    *num = number_of_tests->valueint;

    return SUCCESS;
}

int load_from_json_CBOR_IN(test_cbor_ctx ctx, int num, uint8_t *buf, size_t blen) {
    cJSON *in;

    char in_key[5];

    memset(in_key, 0, sizeof(in_key));
    snprintf(in_key, sizeof(in_key), "in%d", num);

    if (!cJSON_IsObject(ctx->root)) {
        return FAILURE;
    }

    if ((in = cJSON_GetObjectItemCaseSensitive(ctx->root, in_key)) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(in, buf, blen);
}

int load_from_json_CBOR_OUT(test_cbor_ctx ctx, int num, uint8_t *buf, size_t blen) {
    cJSON *out;

    char out_key[5];

    memset(out_key, 0, sizeof(out_key));
    snprintf(out_key, sizeof(out_key), "out%d", num);

    if ((out = cJSON_GetObjectItemCaseSensitive(ctx->root, out_key)) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(out, buf, blen);
}
