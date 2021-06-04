#include <sys/socket.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#include <edhoc/edhoc.h>
#include <edhoc/creddb.h>

#if defined(EDHOC_AUTH_X509_CERT)
#if defined(MBEDTLS)
#include <mbedtls/x509_crt.h>
#else
#error "No X509 backend enabled"
#endif
#else
#error "This example requires EDHOC_AUTH_X509_CERT to be active"
#endif

#include "util.h"
#include "nanocoap.h"

#if defined(WOLFSSL)

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
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

#define MAX_BUF_SIZE    (512)

edhoc_ctx_t ctx;

bool epk = true;

const uint8_t cid[] = {0x00};

// CBOR-encoded ephemeral key
const uint8_t cborEphKey[] = {0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x71, 0xa3, 0xd5, 0x99, 0xc2, 0x1d, 0xa1,
                              0x89, 0x02, 0xa1, 0xae, 0xa8, 0x10, 0xb2, 0xb6, 0x38, 0x2c, 0xcd, 0x8d, 0x5f, 0x9b, 0xf0,
                              0x19, 0x52, 0x81, 0x75, 0x4c, 0x5e, 0xbc, 0xaf, 0x30, 0x1e, 0x23, 0x58, 0x20, 0xfd, 0x8c,
                              0xd8, 0x77, 0xc9, 0xea, 0x38, 0x6e, 0x6a, 0xf3, 0x4f, 0xf7, 0xe6, 0x06, 0xc4, 0xb6, 0x4c,
                              0xa8, 0x31, 0xc8, 0xba, 0x33, 0x13, 0x4f, 0xd4, 0xcd, 0x71, 0x67, 0xca, 0xba, 0xec, 0xda};


ssize_t edhoc_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context);


/* must be sorted by path (ASCII order) */
const coap_resource_t coap_resources[] = {
        // URI, allowed methods, handler, context object
        {"/.well-known/edhoc", COAP_POST, edhoc_handler, &ctx},
};

const unsigned coap_resources_numof = (sizeof(coap_resources) / sizeof(*coap_resources));

_Noreturn int nanocoap_server(void) {

    int sockfd, n;
    socklen_t len;
    struct sockaddr_in servaddr, cliaddr;

    uint8_t buffer[MAX_BUF_SIZE];

    // setting up UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(COAP_PORT);

    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        perror("setsockopt():");
        exit(EXIT_FAILURE);
    }

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    len = sizeof(cliaddr);
    while (1) {
        n = recvfrom(sockfd, (char *) buffer, MAX_BUF_SIZE, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
        if (n < 0) {
            perror("recvfrom()");
        } else if (n > 0) {
            coap_pkt_t pkt;
            if (coap_parse(&pkt, (uint8_t *) buffer, n) < 0) {
                DEBUG("error parsing packet\n");
                continue;
            }

            if ((n = coap_handle_req(&pkt, buffer, MAX_BUF_SIZE)) > 0) {
                if (sendto(sockfd, buffer, n, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len) < 0) {
                    perror("sendto()");
                }
            } else {
                DEBUG("error handling request %d\n", (int) n);
            }
        }
    }

}

ssize_t edhoc_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context) {
    edhoc_ctx_t *ctxPtr;
    ssize_t msgLen;

    uint8_t msgBuf[200];
    uint8_t masterSecret[16];
    uint8_t masterSalt[8];

    DEBUG("received an EDHOC message (len %d)\n", pkt->payload_len);
    print_bstr(pkt->payload, pkt->payload_len);

    msgLen = 0;
    ctxPtr = (edhoc_ctx_t *) context;

    if (ctxPtr->state == EDHOC_WAITING) {
        if ((msgLen = edhoc_create_msg2(ctxPtr, pkt->payload, pkt->payload_len, msgBuf, sizeof(msgBuf))) < 0) {
            DEBUG("Handshake failed with error code: %ld\n", msgLen);
            return msgLen;
        } else {
            DEBUG("Sending message (%ld bytes):\n", msgLen);
            print_bstr(msgBuf, (long) msgLen);
            msgLen = coap_reply_simple(pkt, COAP_CODE_204, buf, len, 0, msgBuf, msgLen);
        }
    } else if (ctxPtr->state == EDHOC_SENT_MESSAGE_2) {
        if ((msgLen = edhoc_resp_finalize(ctxPtr, pkt->payload, pkt->payload_len, false, NULL, 0)) < 0) {
            DEBUG("Handshake failed with error code: %ld\n", msgLen);
            return msgLen;
        } else {
            DEBUG("Sending message (%ld bytes):\n", msgLen);
            print_bstr(msgBuf, (long) msgLen);
            msgLen = coap_reply_simple(pkt, COAP_CODE_204, buf, len, 0, NULL, 0);
        }
    }

    if (ctxPtr->state == EDHOC_FINALIZED) {
        edhoc_exporter(ctxPtr, "OSCORE Master Secret", 16, masterSecret, sizeof(masterSecret));
        edhoc_exporter(ctxPtr, "OSCORE Master Salt", 8, masterSalt, sizeof(masterSalt));

        DEBUG("OSCORE MASTER SECRET:\n");
        print_bstr(masterSecret, sizeof(masterSecret));

        DEBUG("\nOSCORE MASTER SALT:\n");
        print_bstr(masterSalt, sizeof(masterSalt));
    }


    return msgLen;
}

int main(void) {
    // setting up EDHOC context
    edhoc_conf_t conf;

    cred_id_t credIdCtx;
#if defined(MBEDTLS)
    mbedtls_x509_crt x509Ctx;
#else
#error "No X509 backend enabled"
#endif

    cose_key_t authKey;

#if defined(WOLFSSL)
    wc_Sha256 thCtx;
    wc_InitSha256(&thCtx);
#elif defined(HACL)
    hacl_Sha256 thCtx;
#elif defined(TINYCRYPT)
    struct tc_sha256_state_struct thCtx;
#else
#error "No crypto backend enabled."
#endif

    DEBUG("Set up EDHOC configuration...\n");
    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    cose_key_init(&authKey);
    if (cose_key_from_cbor(&authKey, x509_auth_key_resp_tv1, x509_auth_key_resp_tv1_len) != EDHOC_SUCCESS) {
        DEBUG("Failed to load authentication key... Aborting!\n");
        return -1;
    }

    if (edhoc_load_ephkey(&ctx, cborEphKey, sizeof(cborEphKey)) != EDHOC_SUCCESS) {
        DEBUG("Failed to load ephemeral key... Aborting!\n");
        return -1;
    }

    if (edhoc_session_preset_cidr(&ctx, cid, sizeof(cid)) != EDHOC_SUCCESS) {
        DEBUG("Failed to load connection identifier... Aborting!\n");
        return -1;
    }

    cred_id_init(&credIdCtx);
    if (cred_id_from_cbor(&credIdCtx, x509_der_cert_resp_id_tv1, x509_der_cert_resp_id_tv1_len) != EDHOC_SUCCESS) {
        DEBUG("Failed to load credential identifier... Aborting!\n");
        return -1;
    }

#if defined(EDHOC_AUTH_X509_CERT)
    cred_x509_init(&x509Ctx);
    // TODO: return code is negative, because we are loading a fake certificate
    cred_x509_from_der(&x509Ctx, x509_der_cert_resp_tv1, x509_der_cert_resp_tv1_len);

    if (edhoc_conf_setup_credentials(&conf, &authKey, CRED_TYPE_DER_CERT, &x509Ctx, &credIdCtx, f_remote_creds) !=
        EDHOC_SUCCESS) {
        DEBUG("Failed to load EDHOC configuration... Aborting!\n");
        return -1;
    }
#else
#error "This example requires EDHOC_AUTH_X509_CERT to be active"
#endif

    if (edhoc_conf_setup_role(&conf, EDHOC_IS_RESPONDER) != EDHOC_SUCCESS) {
        DEBUG("Failed to load EDHOC role... Aborting!\n");
        return -1;
    }

    edhoc_conf_setup_ad_callbacks(&conf, NULL, NULL, NULL);

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf, &thCtx);

    // following edhoc configuration methods are purely for debugging purposes
    // >>>>>>>>>>>>>>>>>>>>>>
    if (epk) {
        if (edhoc_load_ephkey(&ctx, cborEphKey, sizeof(cborEphKey)) != 0)
            return -1;
    }

    if (edhoc_session_preset_cidr(&ctx, cid, sizeof(cid)) != 0)
        return -1;

    // <<<<<<<<<<<<<<<<<<<<<<

    nanocoap_server();

    return 0;
}
