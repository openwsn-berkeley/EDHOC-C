#include <sys/socket.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#include <edhoc/edhoc.h>

#include "nanocoap.h"

#define MAX_BUF_SIZE    (512)

edhoc_ctx_t ctx;

bool epk = true;

// CBOR-encoded authentication key
const uint8_t auth_key[] = {0xa4, 0x01, 0x01, 0x20, 0x06, 0x23, 0x58, 0x20, 0xdf, 0x69, 0x27, 0x4d, 0x71, 0x32, 0x96,
                            0xe2, 0x46, 0x30, 0x63, 0x65, 0x37, 0x2b, 0x46, 0x83, 0xce, 0xd5, 0x38, 0x1b, 0xfc, 0xad,
                            0xcd, 0x44, 0xa, 0x24, 0xc3, 0x91, 0xd2, 0xfe, 0xdb, 0x94, 0x4, 0x80};


// CBOR-encoded certificate
const uint8_t cbor_cert[] = {0x58, 0x6e, 0x47, 0x62, 0x4d, 0xc9, 0xcd, 0xc6, 0x82, 0x4b, 0x2a, 0x4c, 0x52, 0xe9, 0x5e,
                             0xc9, 0xd6, 0xb0, 0x53, 0x4b, 0x71, 0xc2, 0xb4, 0x9e, 0x4b, 0xf9, 0x03, 0x15, 0x00, 0xce,
                             0xe6, 0x86, 0x99, 0x79, 0xc2, 0x97, 0xbb, 0x5a, 0x8b, 0x38, 0x1e, 0x98, 0xdb, 0x71, 0x41,
                             0x08, 0x41, 0x5e, 0x5c, 0x50, 0xdb, 0x78, 0x97, 0x4c, 0x27, 0x15, 0x79, 0xb0, 0x16, 0x33,
                             0xa3, 0xef, 0x62, 0x71, 0xbe, 0x5c, 0x22, 0x5e, 0xb2, 0x8f, 0x9c, 0xf6, 0x18, 0x0b, 0x5a,
                             0x6a, 0xf3, 0x1e, 0x80, 0x20, 0x9a, 0x08, 0x5c, 0xfb, 0xf9, 0x5f, 0x3f, 0xdc, 0xf9, 0xb1,
                             0x8b, 0x69, 0x3d, 0x6c, 0x0e, 0x0d, 0x0f, 0xfb, 0x8e, 0x3f, 0x9a, 0x32, 0xa5, 0x08, 0x59,
                             0xec, 0xd0, 0xbf, 0xcf, 0xf2, 0xc2, 0x18};

const uint8_t cid[] = {0x2b};

// CBOR-encoded ephemeral key
const uint8_t eph_key[] = {0xa5, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x71, 0xa3, 0xd5, 0x99, 0xc2, 0x1d, 0xa1,
                           0x89, 0x02, 0xa1, 0xae, 0xa8, 0x10, 0xb2, 0xb6, 0x38, 0x2c, 0xcd, 0x8d, 0x5f, 0x9b, 0xf0,
                           0x19, 0x52, 0x81, 0x75, 0x4c, 0x5e, 0xbc, 0xaf, 0x30, 0x1e, 0x23, 0x58, 0x20, 0xfd, 0x8c,
                           0xd8, 0x77, 0xc9, 0xea, 0x38, 0x6e, 0x6a, 0xf3, 0x4f, 0xf7, 0xe6, 0x06, 0xc4, 0xb6, 0x4c,
                           0xa8, 0x31, 0xc8, 0xba, 0x33, 0x13, 0x4f, 0xd4, 0xcd, 0x71, 0x67, 0xca, 0xba, 0xec, 0xda,
                           0x04, 0x80};

// CBOR-encoded credential identifier
const uint8_t cred_id[] = {0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xfc, 0x79, 0x99, 0x0f, 0x24, 0x31, 0xa3, 0xf5};


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

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

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
    edhoc_ctx_t *ctx_ptr;

    ctx_ptr = (edhoc_ctx_t *) context;



    return 0;
}

int main(void) {
    // setting up EDHOC context
    cbor_cert_t cert;
    edhoc_conf_t conf;

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    DEBUG("Set up EDHOC configuration...\n");
    if (edhoc_conf_setup(&conf, EDHOC_IS_RESPONDER, NULL, NULL, NULL) != 0)
        return -1;

    edhoc_cred_cbor_cert_init(&cert);
    if (edhoc_cred_load_cbor_cert(&cert, cbor_cert, sizeof(cbor_cert)) != 0)
        return -1;

    DEBUG("Load private authentication key...\n");
    edhoc_conf_load_authkey(&conf, auth_key, sizeof(auth_key));

    DEBUG("Load CBOR certificate...\n");
    edhoc_conf_load_credentials(&conf, CRED_TYPE_CBOR_CERT, &cert, NULL);

    DEBUG("Load credential identifier\n");
    if (edhoc_conf_load_cred_id(&conf, cred_id, CRED_ID_TYPE_X5T, sizeof(cred_id)) != 0)
        return -1;

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf);

    // following edhoc configuration methods are purely for debugging purposes
    // >>>>>>>>>>>>>>>>>>>>>>
    if (!epk) {
        if (edhoc_load_ephkey(&ctx, eph_key, sizeof(eph_key)) != 0)
            return -1;
    }

    if (edhoc_session_preset_cidr(&ctx, cid, sizeof(cid)) != 0)
        return -1;

    // <<<<<<<<<<<<<<<<<<<<<<

    nanocoap_server();

    return 0;
}