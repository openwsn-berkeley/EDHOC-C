#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

#include <edhoc/edhoc.h>
#include <edhoc/credentials.h>
#include <edhoc/creddb.h>

#include <mbedtls/x509_crt.h>

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

#include "util.h"

#define PORT        (9830)

// #define IPV6

int counter = 1;

// CBOR-encoded certificate
const uint8_t cid[] = {0x00};

// CBOR-encoded ephemeral key
const uint8_t cborEphKey[] = {0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x71, 0xa3, 0xd5, 0x99, 0xc2, 0x1d, 0xa1,
                              0x89, 0x02, 0xa1, 0xae, 0xa8, 0x10, 0xb2, 0xb6, 0x38, 0x2c, 0xcd, 0x8d, 0x5f, 0x9b, 0xf0,
                              0x19, 0x52, 0x81, 0x75, 0x4c, 0x5e, 0xbc, 0xaf, 0x30, 0x1e, 0x23, 0x58, 0x20, 0xfd, 0x8c,
                              0xd8, 0x77, 0xc9, 0xea, 0x38, 0x6e, 0x6a, 0xf3, 0x4f, 0xf7, 0xe6, 0x06, 0xc4, 0xb6, 0x4c,
                              0xa8, 0x31, 0xc8, 0xba, 0x33, 0x13, 0x4f, 0xd4, 0xcd, 0x71, 0x67, 0xca, 0xba, 0xec, 0xda};



// CBOR-encoded credential identifier

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
    if (cose_key_from_cbor(&authKey, x509_auth_key_resp_tv1, x509_auth_key_resp_tv1_len) != EDHOC_SUCCESS) {
        printf("[%d] Failed to load authentication key... Aborting!\n", counter++);
        return -1;
    }

    if (edhoc_load_ephkey(&ctx, cborEphKey, sizeof(cborEphKey)) != EDHOC_SUCCESS) {
        printf("[%d] Failed to load ephemeral key... Aborting!\n", counter++);
        return -1;
    }

    if (edhoc_session_preset_cidr(&ctx, cid, sizeof(cid)) != EDHOC_SUCCESS) {
        printf("[%d] Failed to load connection identifier... Aborting!\n", counter++);
        return -1;
    }

    cred_id_init(&credIdCtx);
    if (cred_id_from_cbor(&credIdCtx, x509_der_cert_resp_id_tv1, x509_der_cert_resp_id_tv1_len) != EDHOC_SUCCESS) {
        printf("[%d] Failed to load credential identifier... Aborting!\n", counter++);
        return -1;
    }

    cred_x509_init(&x509Ctx);
    // TODO: return code is negative, because we are loading a fake certificate
    cred_x509_from_der(&x509Ctx, x509_der_cert_resp_tv1, x509_der_cert_resp_tv1_len);

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

    if ((bread = read(sockfd, incoming, sizeof(incoming))) <= 0)
        return -1;

    printf("[%d] Received a message (%ld):\n", counter++, bread);
    print_bstr(incoming, bread);

    if ((len = edhoc_create_msg2(&ctx, incoming, bread, outgoing, sizeof(outgoing))) > 0) {
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

    edhoc_resp_finalize(&ctx, incoming, bread, false, NULL, 0);

    printf("[%d] Received a message (%ld bytes):\n", counter++, bread);
    print_bstr(incoming, bread);

    printf("[%d] Handshake successfully completed...\n", counter++);
    printf("[%d] Transcript hash 4:\n", counter++);
    print_bstr(ctx.session.th4, EDHOC_DIGEST_SIZE);

    uint8_t oscore_secret[16];
    uint8_t oscore_salt[8];

    printf("[%d] OSCORE Master Secret:\n", counter++);
    edhoc_exporter(&ctx, "OSCORE Master Secret", 16, oscore_secret, sizeof(oscore_secret));
    print_bstr(oscore_secret, 16);

    printf("[%d] OSCORE Master Salt:\n", counter++);
    edhoc_exporter(&ctx, "OSCORE Master Salt", 8, oscore_salt, sizeof(oscore_salt));
    print_bstr(oscore_salt, 8);

    return 0;
}


int main(int argc, char **argv) {
    ssize_t ret;
    ssize_t errc;

    int sockfd, connfd;
    socklen_t client_addr_len;
#if defined(IPV6)
    struct sockaddr_in6 servaddr, cli;
#else
    struct sockaddr_in servaddr, cli;
#endif

    ret = -1;

#if defined(IPV6)
    sockfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == -1) {
        printf("[ERR] Socket creation failed...\n");
        goto exit;
    }

    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        printf("[ERR] setsockopt(SO_REUSEADDR) failed...\n");

    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_addr = in6addr_any;
    servaddr.sin6_port = htons(PORT);

#else

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("[ERR] Socket creation failed...\n");
        goto exit;
    }

    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        printf("[ERR] setsockopt(SO_REUSEADDR) failed...\n");

    memset(&servaddr, 0, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

#endif

    // Binding newly created socket to given IP and verification
    if ((errc = bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr))) != 0) {
        printf("[ERR] Socket bind failed with err: %ld\n", errc);
        goto exit;
    }

    if ((listen(sockfd, 5)) != 0) {
        printf("[ERR] Listen failed...\n");
        goto exit;
    }

    printf("[%d] Start listening on port: %d...\n", counter++, PORT);

    client_addr_len = sizeof(cli);
    connfd = accept(sockfd, (struct sockaddr *) &cli, (socklen_t *) &client_addr_len);
    if (connfd < 0) {
        perror("accept()");
        printf("[ERR] server accept failed... (error: %d)\n", connfd);
        goto exit;
    }

    printf("[%d] Accepting client...\n", counter++);

    edhoc_handshake(connfd);

    printf("[%d] Closing socket...\n", counter++);
    close(sockfd);

    ret = 0;
    exit:
    return ret;
}