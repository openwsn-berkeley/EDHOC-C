#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <cjson/cJSON.h>

#include "json.h"

struct test_cred_ctx {
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

test_cred_ctx load_json_cred_test_file(const char *filename) {
    unsigned long read_size;
    unsigned long name_len;
    test_cred_ctx ctx;
    FILE *fp;

    if ((ctx = malloc(sizeof(struct test_cred_ctx))) == NULL) {
        return NULL;
    }

    // clear test_context
    memset(ctx, 0, sizeof(struct test_cred_ctx));

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

        close_cred_test(ctx);

        return NULL;
    }

    // start JSON parsing
    ctx->root = cJSON_Parse(ctx->json_buffer);

    if (!cJSON_IsObject(ctx->root)) {
        close_cred_test(ctx);

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

void close_cred_test(test_cred_ctx ctx) {

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
    size_t i, hex_len, hex_string_len;

    if (!cJSON_IsString(string)) {
        return FAILURE;
    }

    hex_string = cJSON_GetStringValue(string);
    hex_string_len = strlen(hex_string);
    hex_len = hex_string_len / 2;
    pos = hex_string;

    if (hex_len > blen || hex_string_len % 2 != 0) {
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

int load_from_json_SIGNATURE2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *signature_2;

    if ((signature_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "signature_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(signature_2, buf, blen);
}

int load_from_json_SIGNATURE3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *signature_3;

    if ((signature_3 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "signature_3")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(signature_3, buf, blen);
}

int load_from_json_A2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *a_2m;

    if ((a_2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "a_2m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(a_2m, buf, blen);
}

int load_from_json_A3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *a_3m;

    if ((a_3m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "a_3m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(a_3m, buf, blen);
}

int load_from_json_M2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *m_2;

    if ((m_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "m_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(m_2, buf, blen);
}

int load_from_json_M3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *m_3;

    if ((m_3 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "m_3")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(m_3, buf, blen);
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

int load_from_json_DATA3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *data_3;

    if ((data_3 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "data_3")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(data_3, buf, blen);
}

int load_from_json_PRK2E(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *prk_2e;

    if ((prk_2e = cJSON_GetObjectItemCaseSensitive(ctx->shared, "prk_2e")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(prk_2e, buf, blen);
}

int load_from_json_PRK3E2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *prk_3e2m;

    if ((prk_3e2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "prk_3e2m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(prk_3e2m, buf, blen);
}

int load_from_json_PRK4X3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *prk_4x3m;

    if ((prk_4x3m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "prk_4x3m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(prk_4x3m, buf, blen);
}

int load_from_json_K2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *k_2m;

    if ((k_2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "k_2m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(k_2m, buf, blen);
}

int load_from_json_K3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *k_3m;

    if ((k_3m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "k_3m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(k_3m, buf, blen);
}

int load_from_json_INFO_K2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *info_k_2m;

    if ((info_k_2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "info_k_2m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(info_k_2m, buf, blen);
}

int load_from_json_INFO_K3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *info_k_3m;

    if ((info_k_3m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "info_k_3m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(info_k_3m, buf, blen);
}

int load_from_json_IV2M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *iv_2m;

    if ((iv_2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "iv_2m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(iv_2m, buf, blen);
}

int load_from_json_IV3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *iv_3m;

    if ((iv_3m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "iv_3m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(iv_3m, buf, blen);
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
    cJSON *info_iv_2m;

    if ((info_iv_2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "info_iv_2m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(info_iv_2m, buf, blen);
}

int load_from_json_INFO_IV3M(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *info_iv_3m;

    if ((info_iv_3m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "info_iv_3m")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(info_iv_3m, buf, blen);
}

int load_from_json_INPUT_TH2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *input_th_2;

    if ((input_th_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "input_th_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(input_th_2, buf, blen);
}

int load_from_json_TH2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *th_2;

    if ((th_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "th_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(th_2, buf, blen);
}

int load_from_json_INPUT_TH3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *input_th_3;

    if ((input_th_3 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "input_th_3")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(input_th_3, buf, blen);
}

int load_from_json_TH3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *th_3;

    if ((th_3 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "th_3")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(th_3, buf, blen);
}

int load_from_json_INPUT_TH4(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *input_th_4;

    if ((input_th_4 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "input_th_4")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(input_th_4, buf, blen);
}

int load_from_json_TH4(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *th_4;

    if ((th_4 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "th_4")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(th_4, buf, blen);
}

int load_from_json_INFO_KEYSTREAM(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *info_keystream_2;

    if ((info_keystream_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "info_keystream_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(info_keystream_2, buf, blen);
}

int load_from_json_KEYSTREAM(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *keystream_2;

    if ((keystream_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "keystream_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(keystream_2, buf, blen);
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

int load_from_json_MAC2(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *mac_2;

    if ((mac_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "mac_2")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(mac_2, buf, blen);
}

int load_from_json_MAC3(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *mac_3;

    if ((mac_3 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "mac_3")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(mac_3, buf, blen);
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

int load_from_json_G_R(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *g_r;

    if ((g_r = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "g_r")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(g_r, buf, blen);
}

int load_from_json_G_I(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *g_i;

    if ((g_i = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "g_i")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(g_i, buf, blen);
}

int load_from_json_R(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *r;

    if ((r = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "r")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(r, buf, blen);
}

int load_from_json_I(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *i;

    if ((i = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "i")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(i, buf, blen);
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

int load_from_json_CBORCERT(test_cred_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *cborCert;

    if ((cborCert = cJSON_GetObjectItemCaseSensitive(ctx->root, "cborCert")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(cborCert, buf, blen);
}


int load_from_json_CBORCERT_TYPE(test_cred_ctx ctx, int *value) {
    cJSON *cert_type;

    if ((cert_type = cJSON_GetObjectItemCaseSensitive(ctx->root, "cborCertificateType")) == NULL) {
        return FAILURE;
    }

    *value = cert_type->valueint;

    return SUCCESS;
}

int load_from_json_CBORCERT_SERIALNUMBER(test_cred_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *serialNumber;

    if ((serialNumber = cJSON_GetObjectItemCaseSensitive(ctx->root, "certificateSerialNumber")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(serialNumber, buf, blen);
}

int load_from_json_CBORCERT_ISSUER(test_cred_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *issuer;

    if ((issuer = cJSON_GetObjectItemCaseSensitive(ctx->root, "issuer")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(issuer, buf, blen);
}

int load_from_json_CBORCERT_SUBJECT(test_cred_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *subject;

    if ((subject = cJSON_GetObjectItemCaseSensitive(ctx->root, "subject")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(subject, buf, blen);
}

int load_from_json_CBORCERT_SUBJECTPKA(test_cred_ctx ctx, int *value) {
    cJSON *subjectPKA;

    if ((subjectPKA = cJSON_GetObjectItemCaseSensitive(ctx->root, "subjectPublicKeyAlgorithm")) == NULL) {
        return FAILURE;
    }

    *value = subjectPKA->valueint;

    return SUCCESS;
}

int load_from_json_CBORCERT_SUBJECTPK(test_cred_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *subjectPK;

    if ((subjectPK = cJSON_GetObjectItemCaseSensitive(ctx->root, "subjectPublicKey")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(subjectPK, buf, blen);
}

int load_from_json_CBORCERT_ISSUERALGORITHM(test_cred_ctx ctx, int *value) {
    cJSON *issuerAlg;

    if ((issuerAlg = cJSON_GetObjectItemCaseSensitive(ctx->root, "issuerSignatureAlgorithm")) == NULL) {
        return FAILURE;
    }

    *value = issuerAlg->valueint;

    return SUCCESS;
}

int load_from_json_CBORCERT_SIGNATURE(test_cred_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *signature;

    if ((signature = cJSON_GetObjectItemCaseSensitive(ctx->root, "issuerSignatureValue")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(signature, buf, blen);
}

int load_from_json_RPK(test_cred_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *rpk;

    if ((rpk = cJSON_GetObjectItemCaseSensitive(ctx->root, "rpk")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(rpk, buf, blen);
}

int load_from_json_RPK_X(test_cred_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *x;

    if ((x = cJSON_GetObjectItemCaseSensitive(ctx->root, "x")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(x, buf, blen);
}

int load_from_json_RPK_D(test_cred_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *d;

    if ((d = cJSON_GetObjectItemCaseSensitive(ctx->root, "d")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(d, buf, blen);
}

int load_from_json_RPK_CURVE(test_cred_ctx ctx, int *value) {
    cJSON *curve;

    if ((curve = cJSON_GetObjectItemCaseSensitive(ctx->root, "crv")) == NULL) {
        return FAILURE;
    }

    *value = curve->valueint;

    return SUCCESS;
}

int load_from_json_INFO_OSCORE_SECRET(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *infoOscoreSec;

    if ((infoOscoreSec = cJSON_GetObjectItemCaseSensitive(ctx->shared, "info_oscore_sec")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(infoOscoreSec, buf, blen);
}


int load_from_json_INFO_OSCORE_SALT(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *infoOscoreSalt;

    if ((infoOscoreSalt = cJSON_GetObjectItemCaseSensitive(ctx->shared, "info_oscore_salt")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(infoOscoreSalt, buf, blen);
}

int load_from_json_OSCORE_SECRET(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *oscoreSecret;

    if ((oscoreSecret = cJSON_GetObjectItemCaseSensitive(ctx->shared, "oscore_secret")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(oscoreSecret, buf, blen);
}

int load_from_json_OSCORE_SALT(test_edhoc_ctx ctx, uint8_t *buf, size_t blen) {
    cJSON *oscoreSalt;

    if ((oscoreSalt = cJSON_GetObjectItemCaseSensitive(ctx->shared, "oscore_salt")) == NULL) {
        return FAILURE;
    }

    return load_json_hexString(oscoreSalt, buf, blen);
}
