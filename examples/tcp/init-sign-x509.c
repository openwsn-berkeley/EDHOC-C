#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <edhoc/edhoc.h>
#include <edhoc/credentials.h>
#include <edhoc/creddb.h>

#if defined(WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#elif defined(HACL)

#define HASH_INPUT_BLEN     (256)

typedef struct hacl_Sha256 hacl_Sha256;

struct hacl_Sha256 {
    uint16_t fillLevel;
    uint8_t buffer[HASH_INPUT_BLEN];
};
#elif defined(TINYCRYPT)
#include "../../src/crypto/tinycrypt/sha256.h"
#endif

#include <mbedtls/x509_crt.h>

#include "util.h"

#define PORT            (9830)
// #define IPV6

int counter = 1;

corr_t corr = CORR_1_2;
uint8_t method = EDHOC_AUTH_SIGN_SIGN;
uint8_t suite = EDHOC_CIPHER_SUITE_0;

// CBOR-encoded certificate
const uint8_t cid[] = {0x09};

// CBOR-encoded ephemeral key
const uint8_t cborEphKey[] = {0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x89, 0x8f, 0xf7, 0x9a, 0x02, 0x06, 0x7a,
                              0x16, 0xea, 0x1e, 0xcc, 0xb9, 0x0f, 0xa5, 0x22, 0x46, 0xf5, 0xaa, 0x4d, 0xd6, 0xec, 0x07,
                              0x6b, 0xba, 0x02, 0x59, 0xd9, 0x04, 0xb7, 0xec, 0x8b, 0x0c, 0x23, 0x58, 0x20, 0x8f, 0x78,
                              0x1a, 0x09, 0x53, 0x72, 0xf8, 0x5b, 0x6d, 0x9f, 0x61, 0x09, 0xae, 0x42, 0x26, 0x11, 0x73,
                              0x4d, 0x7d, 0xbf, 0xa0, 0x06, 0x9a, 0x2d, 0xf2, 0x93, 0x5b, 0xb2, 0xe0, 0x53, 0xbf, 0x35};


int edhoc_handshake(int sockfd) {
    ssize_t bread, len, written;
    uint8_t incoming[500], outgoing[500];

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    cred_id_t credIdCtx;
    mbedtls_x509_crt x509Ctx;
    cose_key_t authKey;

#if defined(WOLFSSL)
    wc_Sha256 thCtx;
    wc_InitSha256(&thCtx);
#elif defined(HACL)
    hacl_Sha256 thCtx;
#elif defined(TINYCRYPT)
    tinycrypt_Sha256 thCtx;
#else
#error "No crypto backend enabled."
#endif

    printf("[%d] Set up EDHOC configuration...\n", counter++);

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    cose_key_init(&authKey);
    if (cose_key_from_cbor(&authKey, x509_auth_key_init_tv1, x509_auth_key_init_tv1_len) != EDHOC_SUCCESS) {
        printf("[%d] Failed to load authentication key... Aborting!\n", counter++);
        return -1;
    }

    if (edhoc_load_ephkey(&ctx, cborEphKey, sizeof(cborEphKey)) != EDHOC_SUCCESS) {
        printf("[%d] Failed to load ephemeral key... Aborting!\n", counter++);
        return -1;
    }

    if (edhoc_session_preset_cidi(&ctx, cid, sizeof(cid)) != EDHOC_SUCCESS) {
        printf("[%d] Failed to load connection identifier... Aborting!\n", counter++);
        return -1;
    };

    cred_id_init(&credIdCtx);
    if (cred_id_from_cbor(&credIdCtx, x509_der_cert_init_id_tv1, x509_der_cert_init_id_tv1_len) != EDHOC_SUCCESS) {
        printf("[%d] Failed to load credential identifier... Aborting!\n", counter++);
        return -1;
    }

    cred_x509_init(&x509Ctx);
    // TODO: return code is negative, because we are loading a fake certificate
    cred_x509_from_der(&x509Ctx, x509_der_cert_init_tv1, x509_der_cert_init_tv1_len);

    if (edhoc_conf_setup_credentials(&conf, &authKey, CRED_TYPE_DER_CERT, &x509Ctx, &credIdCtx, f_remote_creds) !=
        EDHOC_SUCCESS) {
        printf("[%d] Failed to load EDHOC configuration... Aborting!\n", counter++);
        return -1;
    }

    if (edhoc_conf_setup_role(&conf, EDHOC_IS_RESPONDER) != EDHOC_SUCCESS) {
        printf("[%d] Failed to load EDHOC role... Aborting!\n", counter++);
        return -1;
    }

    edhoc_conf_setup_ad_callbacks(&conf, NULL, NULL, NULL);

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf, &thCtx);

    if ((len = edhoc_create_msg1(&ctx, corr, method, suite, outgoing, sizeof(outgoing))) > 0) {
        printf("[%d] Sending message (%ld bytes):\n", counter++, len);
        print_bstr(outgoing, len);

        written = write(sockfd, outgoing, len);

        if (written != len) {
            printf("[ERR] Not all bytes were sent...");
            return -1;
        }
    } else {
        return -1;
    }

    if ((bread = read(sockfd, incoming, sizeof(incoming))) <= 0)
        return -1;

    printf("[%d] Received a message (%ld bytes):\n", counter++, bread);
    print_bstr(incoming, bread);

    if ((len = edhoc_create_msg3(&ctx, incoming, bread, outgoing, sizeof(outgoing))) > 0) {
        printf("[%d] Sending message (%ld bytes):\n", counter++, len);
        print_bstr(outgoing, len);

        written = write(sockfd, outgoing, len);

        if (written != len) {
            printf("[ERR] Not all bytes were sent...");
            return -1;
        }
    } else {
        return -1;
    }

    edhoc_init_finalize(&ctx);

    printf("[%d] Handshake successfully completed...\n", counter++);
    printf("[%d] Transcript hash 4:\n", counter++);
    print_bstr(ctx.session.th4, EDHOC_DIGEST_SIZE);

    uint8_t oscore_secret[16];
    uint8_t oscore_salt[8];

    printf("[%d] OSCORE Master Secret:\n", counter++);
    edhoc_exporter(&ctx, "OSCORE Master Secret", 16, oscore_secret, 16);
    print_bstr(oscore_secret, 16);

    printf("[%d] OSCORE Master Salt:\n", counter++);
    edhoc_exporter(&ctx, "OSCORE Master Salt", 8, oscore_salt, 8);
    print_bstr(oscore_salt, 8);

    return 0;
}

int main(int argc, char **argv) {
    int sockfd;
#if defined(IPV6)
    struct sockaddr_in6 servaddr;
#else
    struct sockaddr_in servaddr;
#endif

#if defined(IPV6)
    // socket create and verification
    sockfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == -1) {
        printf("[ERR] socket creation failed...\n");
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &servaddr.sin6_addr);
    servaddr.sin6_port = htons(PORT);
#else
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket()");
        printf("[ERR] socket creation failed...\n");
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);
#endif

    if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) != 0) {
        perror("connect()");
        printf("[ERR] Connection with the server failed...\n");
        return -1;
    }

    printf("[%d] Connecting to server...\n", counter++);

    edhoc_handshake(sockfd);

    printf("[%d] Closing socket...\n", counter++);
    close(sockfd);

    return 0;
}
