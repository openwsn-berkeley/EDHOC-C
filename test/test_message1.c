#include <edhoc/edhoc.h>
#include <assert.h>
#include <stdbool.h>

const uint8_t msg1_buf[] = {0x01, 0x00, 0x58, 0x20, 0x89, 0x8f, 0xf7, 0x9a, 0x02, 0x06, 0x7a, 0x16, 0xea, 0x1e, 0xcc,
                            0xb9, 0x0f, 0xa5, 0x22, 0x46, 0xf5, 0xaa, 0x4d, 0xd6, 0xec, 0x07, 0x6b, 0xba, 0x02, 0x59,
                            0xd9, 0x04, 0xb7, 0xec, 0x8b, 0x0c, 0x40};
const uint8_t g_x[] = {0x89, 0x8f, 0xf7, 0x9a, 0x02, 0x06, 0x7a, 0x16, 0xea, 0x1e, 0xcc, 0xb9, 0x0f, 0xa5, 0x22,
                       0x46, 0xf5, 0xaa, 0x4d, 0xd6, 0xec, 0x07, 0x6b, 0xba, 0x02, 0x59, 0xd9, 0x04, 0xb7, 0xec,
                       0x8b, 0x0c};

bool compare_arrays(const uint8_t a[], const uint8_t b[], int size) {
    for (int i = 0; i < size; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

int decode_message_1() {

    EDHOC_ctx_t ctx;

    assert(EDHOC_Msg1_Decode(&ctx, msg1_buf, sizeof(msg1_buf)) == 0);
    assert(ctx.message_1.method_corr == 1);
    assert(ctx.message_1.g_x_size == sizeof(g_x));
    assert(ctx.message_1.connection_idi == NULL);
    assert(compare_arrays(ctx.message_1.g_x, g_x, ctx.message_1.g_x_size));

    return 0;
}

int build_message_1() {
    EDHOC_ctx_t ctx;
    const uint8_t cipher_list[] = {EDHOC_CIPHER_SUITE_0};
    uint8_t method = SIGN_SIGN;
    uint8_t corr = CORR_1_2;

    EDHOC_Msg1_Build(&ctx, corr, method, cipher_list, sizeof(cipher_list), g_x, sizeof(g_x), NULL, 0, NULL, 0);

    assert(ctx.message_1.method_corr == 1);
    assert(ctx.message_1.g_x_size == sizeof(g_x));
    assert(ctx.message_1.connection_idi == NULL);
    assert(compare_arrays(ctx.message_1.g_x, g_x, ctx.message_1.g_x_size));

    return 0;
}

int encode_message_1() {
    ssize_t msg_size;
    EDHOC_ctx_t ctx;
    const uint8_t cipher_list[] = {EDHOC_CIPHER_SUITE_0};
    uint8_t method = SIGN_SIGN;
    uint8_t corr = CORR_1_2;

    EDHOC_Msg1_Build(&ctx, corr, method, cipher_list, sizeof(cipher_list), g_x, sizeof(g_x), NULL, 0, NULL, 0);

    uint8_t buffer[100];
    msg_size = EDHOC_Msg1_Encode(&ctx, buffer, sizeof(buffer));
    assert(msg_size == 37);
    assert(compare_arrays(buffer, msg1_buf, msg_size));

    return 0;
}

int main(void) {
    decode_message_1();
    build_message_1();
    encode_message_1();
}
