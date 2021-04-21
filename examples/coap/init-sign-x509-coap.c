#include <edhoc/edhoc.h>
#include <mbedtls/x509_crt.h>
#include <edhoc/creddb.h>
#include <util.h>

#include "nanocoap.h"

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

/* must be sorted by path (ASCII order) */
const coap_resource_t coap_resources[] = {};

const unsigned coap_resources_numof = (sizeof(coap_resources) / sizeof(*coap_resources));

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

int main(void) {
    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    cred_id_t credIdCtx;
    mbedtls_x509_crt x509Ctx;
    cose_key_t authKey;

    uint8_t masterSecret[16];
    uint8_t masterSalt[8];

#if defined(WOLFSSL)
    wc_Sha256 thCtx;
    wc_InitSha256(&thCtx);
#elif defined(HACL)
    hacl_Sha256 thCtx;
#elif defined(TINYCRYPT)
    struct tc_sha256_state_struct  thCtx;
#else
#error "No crypto backend enabled."
#endif
    int sockfd, n;
    socklen_t len;
    ssize_t msgLen;
    struct sockaddr_in servaddr;

    // setting up UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(COAP_PORT);

    DEBUG("Set up EDHOC configuration...\n");
    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    cose_key_init(&authKey);
    if (cose_key_from_cbor(&authKey, x509_auth_key_init_tv1, x509_auth_key_init_tv1_len) != EDHOC_SUCCESS) {
        DEBUG("Failed to load authentication key... Aborting!\n");
        return -1;
    }

    if (edhoc_load_ephkey(&ctx, cborEphKey, sizeof(cborEphKey)) != EDHOC_SUCCESS) {
        DEBUG("Failed to load ephemeral key... Aborting!\n");
        return -1;
    }

    if (edhoc_session_preset_cidi(&ctx, cid, sizeof(cid)) != EDHOC_SUCCESS) {
        DEBUG("Failed to load connection identifier... Aborting!\n");
        return -1;
    }

    cred_id_init(&credIdCtx);
    if (cred_id_from_cbor(&credIdCtx, x509_der_cert_init_id_tv1, x509_der_cert_init_id_tv1_len) != EDHOC_SUCCESS) {
        DEBUG("Failed to load credential identifier... Aborting!\n");
        return -1;
    }

    cred_x509_init(&x509Ctx);
    // TODO: return code is negative, because we are loading a fake certificate
    cred_x509_from_der(&x509Ctx, x509_der_cert_init_tv1, x509_der_cert_init_tv1_len);

    if (edhoc_conf_setup_credentials(&conf, &authKey, CRED_TYPE_DER_CERT, &x509Ctx, &credIdCtx, f_remote_creds) !=
        EDHOC_SUCCESS) {
        DEBUG("Failed to load EDHOC configuration... Aborting!\n");
        return -1;
    }

    if (edhoc_conf_setup_role(&conf, EDHOC_IS_INITIATOR) != EDHOC_SUCCESS) {
        DEBUG("Failed to load EDHOC role... Aborting!\n");
        return -1;
    }

    edhoc_conf_setup_ad_callbacks(&conf, NULL, NULL, NULL);

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf, &thCtx);

    coap_pkt_t pkt;
    uint8_t buf1[512] = {0};
    uint8_t buf2[512] = {0};
    uint8_t *pktpos = buf1;

    pkt.hdr = (coap_hdr_t *) buf1;
    pktpos += coap_build_hdr(pkt.hdr, COAP_TYPE_CON, NULL, 0, COAP_METHOD_POST, 1);
    pktpos += coap_opt_put_uri_path(pktpos, 0, "/.well-known/edhoc");
    pkt.payload = pktpos;
    pkt.payload_len = sizeof(buf1) - (pktpos - buf1);
    coap_opt_finish(&pkt, COAP_OPT_FINISH_PAYLOAD);

    if ((msgLen = edhoc_create_msg1(&ctx, corr, method, suite, pkt.payload,
                                    sizeof(buf1) - (pktpos - buf1))) > 0) {
        DEBUG("Sending message (%ld bytes):\n", msgLen);
        print_bstr(pkt.payload, (long) msgLen);
    }

    coap_payload_advance_bytes(&pkt, msgLen);

    if (sendto(sockfd, buf1, sizeof(buf1) - pkt.payload_len, MSG_CONFIRM, (const struct sockaddr *) &servaddr,
               sizeof(servaddr)) < 0) {
        perror("sendto()");
    }

    len = sizeof(servaddr);
    if ((n = recvfrom(sockfd, (char *) buf1, sizeof(buf1), MSG_WAITALL, (struct sockaddr *) &servaddr, &len)) < 0) {
        perror("recvfrom()");
    } else {
        if (coap_parse(&pkt, (uint8_t *) buf1, n) < 0) {
            DEBUG("error parsing packet\n");
            return -1;
        } else {
            DEBUG("received an EDHOC message (len %d)\n", pkt.payload_len);
            print_bstr(pkt.payload, pkt.payload_len);

            if ((msgLen = edhoc_create_msg3(&ctx, pkt.payload, pkt.payload_len, buf2, sizeof(buf2))) < 0) {
                DEBUG("Handshake failed with error code: %ld\n", msgLen);
                return msgLen;
            } else {
                DEBUG("Sending message (%ld bytes):\n", msgLen);
                print_bstr(buf2, (long) msgLen);

                pktpos = buf1;
                pkt.hdr = (coap_hdr_t *) buf1;
                pktpos += coap_build_hdr(pkt.hdr, COAP_TYPE_CON, NULL, 0, COAP_METHOD_POST, 1);
                pktpos += coap_opt_put_uri_path(pktpos, 0, "/.well-known/edhoc");
                pkt.payload = pktpos;
                pkt.payload_len = sizeof(buf1) - (pktpos - buf1);
                coap_opt_finish(&pkt, COAP_OPT_FINISH_PAYLOAD);

                msgLen = coap_payload_put_bytes(&pkt, buf2, msgLen) +  (pktpos - buf1) + 1;
            }
        }
    }

    if (sendto(sockfd, buf1, msgLen, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("sendto()");
    }

    edhoc_init_finalize(&ctx);

    if (ctx.state == EDHOC_FINALIZED) {
        edhoc_exporter(&ctx, "OSCORE Master Secret", 16, masterSecret, sizeof(masterSecret));
        edhoc_exporter(&ctx, "OSCORE Master Salt", 8, masterSalt, sizeof(masterSalt));

        DEBUG("OSCORE MASTER SECRET:\n");
        print_bstr(masterSecret, sizeof(masterSecret));

        DEBUG("\nOSCORE MASTER SALT:\n");
        print_bstr(masterSalt, sizeof(masterSalt));
    }

    return 0;
}
