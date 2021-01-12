#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <cjson/cJSON.h>

#include "json.h"

struct test_context {
    char *filename;
    unsigned long json_size;
    char *json_buffer;
    const cJSON *root;
    const cJSON *initiator;
    const cJSON *responder;
    const cJSON *shared;
};

test_context_ptr load_json_test_file(const char *filename) {
    unsigned long read_size;
    unsigned long name_len;
    test_context_ptr ctx;
    FILE *fp;
    cJSON *root;

    if ((ctx = malloc(sizeof(struct test_context))) == NULL) {
        return NULL;
    }

    // clear test_context
    memset(ctx, 0, sizeof(struct test_context));

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

        close_test(ctx);

        return NULL;
    }

    // start JSON parsing
    root = cJSON_Parse(ctx->json_buffer);

    if (!cJSON_IsObject(root)) {
        close_test(ctx);

        return NULL;
    }

    if ((ctx->initiator = cJSON_GetObjectItemCaseSensitive(root, "I")) == NULL) {
        close_test(ctx);
        return NULL;
    }

    if ((ctx->responder = cJSON_GetObjectItemCaseSensitive(root, "R")) == NULL) {
        close_test(ctx);
        return NULL;
    }

    if ((ctx->shared = cJSON_GetObjectItemCaseSensitive(root, "S")) == NULL) {
        close_test(ctx);
        return NULL;
    }

    return ctx;
}

void close_test(test_context_ptr ctx) {

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

static int load_json_array(cJSON *array, uint8_t *buf, size_t blen) {
    int len;
    int counter;

    cJSON *iterator;

    if (!cJSON_IsArray(array)) {
        return FAILURE;
    }

    len = cJSON_GetArraySize(array);

    if (len > blen) {
        return FAILURE;
    }

    counter = 0;
    cJSON_ArrayForEach(iterator, array) {
        if (cJSON_IsNumber(iterator)) {
            buf[counter] = iterator->valueint;
            counter++;
        } else {
            return FAILURE;
        }
    }

    assert(counter == len);

    return len;
}

int load_from_json_MESSAGE1(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *message1;

    if ((message1 = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "message_1")) == NULL) {
        return FAILURE;
    }

    return load_json_array(message1, buf, blen);
}

int load_from_json_MESSAGE2(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *message2;

    if ((message2 = cJSON_GetObjectItemCaseSensitive(ctx->responder, "message_2")) == NULL) {
        return FAILURE;
    }

    return load_json_array(message2, buf, blen);
}

int load_from_json_DATA2(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *data_2;

    if ((data_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "data_2")) == NULL) {
        return FAILURE;
    }

    return load_json_array(data_2, buf, blen);
}

int load_from_json_INIT_SALT(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *salt;

    if ((salt = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "salt")) == NULL) {
        return FAILURE;
    }

    return load_json_array(salt, buf, blen);
}

int load_from_json_RESP_SALT(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *salt;

    if ((salt = cJSON_GetObjectItemCaseSensitive(ctx->responder, "salt")) == NULL) {
        return FAILURE;
    }

    return load_json_array(salt, buf, blen);
}

int load_from_json_PRK2E(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *prk2e;

    if ((prk2e = cJSON_GetObjectItemCaseSensitive(ctx->shared, "prk2e")) == NULL) {
        return FAILURE;
    }

    return load_json_array(prk2e, buf, blen);
}

int load_from_json_PRK3E2M(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *prk3e2m;

    if ((prk3e2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "prk3e2m")) == NULL) {
        return FAILURE;
    }

    return load_json_array(prk3e2m, buf, blen);
}

int load_from_json_K2M(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *k2m;

    if ((k2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "k2m")) == NULL) {
        return FAILURE;
    }

    return load_json_array(k2m, buf, blen);
}

int load_from_json_INFO_K2M(test_context_ptr ctx, uint8_t *buf, size_t blen){
    cJSON *info_k2m;

    if ((info_k2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "info_k2m")) == NULL) {
        return FAILURE;
    }

    return load_json_array(info_k2m, buf, blen);
}

int load_from_json_IV2M(test_context_ptr ctx, uint8_t *buf, size_t blen){
    cJSON *iv2m;

    if ((iv2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "iv2m")) == NULL) {
        return FAILURE;
    }

    return load_json_array(iv2m, buf, blen);
}

int load_from_json_RESP_CERT(test_context_ptr ctx, uint8_t *buf, size_t blen){
    cJSON *cert;

    if ((cert = cJSON_GetObjectItemCaseSensitive(ctx->responder, "cert")) == NULL) {
        return FAILURE;
    }

    return load_json_array(cert, buf, blen);
}

int load_from_json_RESP_X5T(test_context_ptr ctx, uint8_t *buf, size_t blen){
    cJSON *x5t;

    if ((x5t = cJSON_GetObjectItemCaseSensitive(ctx->responder, "x5t")) == NULL) {
        return FAILURE;
    }

    return load_json_array(x5t, buf, blen);
}

int load_from_json_INFO_IV2M(test_context_ptr ctx, uint8_t *buf, size_t blen){
    cJSON *info_iv2m;

    if ((info_iv2m = cJSON_GetObjectItemCaseSensitive(ctx->shared, "info_iv2m")) == NULL) {
        return FAILURE;
    }

    return load_json_array(info_iv2m, buf, blen);
}

int load_from_json_TH2(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *th_2;

    if ((th_2 = cJSON_GetObjectItemCaseSensitive(ctx->shared, "th_2")) == NULL) {
        return FAILURE;
    }

    return load_json_array(th_2, buf, blen);
}

int load_from_json_INIT_EPHKEY(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *eph_key;

    if ((eph_key = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "eph_key")) == NULL) {
        return FAILURE;
    }

    return load_json_array(eph_key, buf, blen);
}

int load_from_json_INIT_AUTHKEY(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *auth_key;

    if ((auth_key = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "auth_key")) == NULL) {
        return FAILURE;
    }

    return load_json_array(auth_key, buf, blen);
}

int load_from_json_RESP_AUTHKEY(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *auth_key;

    if ((auth_key = cJSON_GetObjectItemCaseSensitive(ctx->responder, "auth_key")) == NULL) {
        return FAILURE;
    }

    return load_json_array(auth_key, buf, blen);
}

int load_from_json_RESP_EPHKEY(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *eph_key;

    if ((eph_key = cJSON_GetObjectItemCaseSensitive(ctx->responder, "eph_key")) == NULL) {
        return FAILURE;
    }

    return load_json_array(eph_key, buf, blen);
}

int load_from_json_DH_SECRET(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *secret;

    if ((secret = cJSON_GetObjectItemCaseSensitive(ctx->shared, "secret")) == NULL) {
        return FAILURE;
    }

    return load_json_array(secret, buf, blen);
}

int load_from_json_G_X(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *g_x;

    if ((g_x = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "g_x")) == NULL) {
        return FAILURE;
    }

    return load_json_array(g_x, buf, blen);
}

int load_from_json_CONN_IDI(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *conn_id;

    if ((conn_id = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "conn_id")) == NULL) {
        return FAILURE;
    }

    return load_json_array(conn_id, buf, blen);
}

int load_from_json_CONN_IDR(test_context_ptr ctx, uint8_t *buf, size_t blen) {
    cJSON *conn_id;

    if ((conn_id = cJSON_GetObjectItemCaseSensitive(ctx->responder, "conn_id")) == NULL) {
        return FAILURE;
    }

    return load_json_array(conn_id, buf, blen);
}

int load_from_json_CORR(test_context_ptr ctx, int *value) {
    cJSON *correlation;

    if (!cJSON_IsObject(ctx->initiator)) {
        return FAILURE;
    }

    if ((correlation = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "correlation")) == NULL) {
        return FAILURE;
    }

    *value = correlation->valueint;

    return 0;
}

int load_from_json_METHOD(test_context_ptr ctx, int *value) {
    cJSON *method;

    if (!cJSON_IsObject(ctx->initiator)) {
        return FAILURE;
    }

    if ((method = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "method")) == NULL) {
        return FAILURE;
    }

    *value = method->valueint;

    return 0;
}

int load_from_json_CIPHERSUITE(test_context_ptr ctx, int *value) {
    cJSON *selected;

    if (!cJSON_IsObject(ctx->initiator)) {
        return FAILURE;
    }

    if ((selected = cJSON_GetObjectItemCaseSensitive(ctx->initiator, "selected")) == NULL) {
        return FAILURE;
    }

    *value = selected->valueint;

    return 0;
}

