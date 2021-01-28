#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suites.h>

#define PORT 9830

// #define IPV6

int counter = 1;

corr_t corr = CORR_1_2;
method_t method = EDHOC_AUTH_SIGN_SIGN;
cipher_suite_t suite = EDHOC_CIPHER_SUITE_0;

const uint8_t cid[] = {};

const uint8_t cbor_cert[] = {0x58, 0x65, 0xfa, 0x34, 0xb2, 0x2a, 0x9c, 0xa4, 0xa1, 0xe1, 0x29, 0x24, 0xea, 0xe1, 0xd1,
                             0x76, 0x60, 0x88, 0x09, 0x84, 0x49, 0xcb, 0x84, 0x8f, 0xfc, 0x79, 0x5f, 0x88, 0xaf, 0xc4,
                             0x9c, 0xbe, 0x8a, 0xfd, 0xd1, 0xba, 0x00, 0x9f, 0x21, 0x67, 0x5e, 0x8f, 0x6c, 0x77, 0xa4,
                             0xa2, 0xc3, 0x01, 0x95, 0x60, 0x1f, 0x6f, 0x0a, 0x08, 0x52, 0x97, 0x8b, 0xd4, 0x3d, 0x28,
                             0x20, 0x7d, 0x44, 0x48, 0x65, 0x02, 0xff, 0x7b, 0xdd, 0xa6, 0x32, 0xc7, 0x88, 0x37, 0x00,
                             0x16, 0xb8, 0x96, 0x5b, 0xdb, 0x20, 0x74, 0xbf, 0xf8, 0x2e, 0x5a, 0x20, 0xe0, 0x9b, 0xec,
                             0x21, 0xf8, 0x40, 0x6e, 0x86, 0x44, 0x2b, 0x87, 0xec, 0x3f, 0xf2, 0x45, 0xb7};

const uint8_t eph_key[] = {0xa5, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x89, 0x8f, 0xf7, 0x9a, 0x02, 0x06, 0x7a,
                           0x16, 0xea, 0x1e, 0xcc, 0xb9, 0x0f, 0xa5, 0x22, 0x46, 0xf5, 0xaa, 0x4d, 0xd6, 0xec, 0x07,
                           0x6b, 0xba, 0x02, 0x59, 0xd9, 0x04, 0xb7, 0xec, 0x8b, 0x0c, 0x23, 0x58, 0x20, 0x8f, 0x78,
                           0x1a, 0x09, 0x53, 0x72, 0xf8, 0x5b, 0x6d, 0x9f, 0x61, 0x09, 0xae, 0x42, 0x26, 0x11, 0x73,
                           0x4d, 0x7d, 0xbf, 0xa0, 0x06, 0x9a, 0x2d, 0xf2, 0x93, 0x5b, 0xb2, 0xe0, 0x53, 0xbf, 0x35,
                           0x04, 0x80};

const uint8_t auth_key[] = {0xa4, 0x01, 0x01, 0x20, 0x06, 0x23, 0x58, 0x20, 0x2f, 0xfc, 0xe7, 0xa0, 0xb2, 0xb8, 0x25,
                            0xd3, 0x97, 0xd0, 0xcb, 0x54, 0xf7, 0x46, 0xe3, 0xda, 0x3f, 0x27, 0x59, 0x6e, 0xe0, 0x6b,
                            0x53, 0x71, 0x48, 0x1d, 0xc0, 0xe0, 0x12, 0xbc, 0x34, 0xd7, 0x04, 0x80};


void print_bstr(const uint8_t *bstr, size_t bstr_len) {
    for (int i = 0; i < bstr_len; i++) {
        if ((i + 1) % 10 == 0)
            printf("0x%02x \n", bstr[i]);
        else
            printf("0x%02x ", bstr[i]);
    }
    printf("\n");
}

int edhoc_handshake(int sockfd) {
    ssize_t cred_id_len, bread, len, written;
    uint8_t cred_id[50];
    uint8_t incoming[500], outgoing[500];

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    printf("[%d] Set up EDHOC configuration...\n", counter++);
    if (edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, NULL, NULL, NULL, NULL, NULL, NULL) != 0)
        return -1;

    printf("[%d] Load private authentication key...\n", counter++);
    edhoc_conf_load_authkey(&conf, auth_key, sizeof(auth_key));

    printf("[%d] Load CBOR certificate...\n", counter++);
    edhoc_conf_load_cborcert(&conf, cbor_cert, sizeof(cbor_cert));

    cred_id_len = cose_x5t_attribute(COSE_ALGO_SHA256_64,
                                     conf.certificate.cert,
                                     conf.certificate.cert_len,
                                     cred_id,
                                     sizeof(cred_id));

    if (cred_id_len < 0)
        return -1;

    printf("[%d] Compute and load CBOR certificate hash:\n", counter++);
    print_bstr(cred_id, cred_id_len);

    if (edhoc_conf_load_cred_id(&conf, cred_id, cred_id_len) != 0)
        return -1;

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf);

    if (edhoc_load_ephkey(&ctx, eph_key, sizeof(eph_key)) != 0)
        return -1;

    if (edhoc_session_preset_cidr(&ctx, cid, sizeof(cid)) != 0)
        return -1;

    if ((len = edhoc_create_msg1(&ctx, corr, method, suite, outgoing, sizeof(outgoing))) > 0) {
        printf("[%d] Sending message (%ld bytes):\n", counter++, len);
        print_bstr(outgoing, len);

        written = write(sockfd, outgoing, len);

        if (written != len) {
            printf("[ERR] Not all bytes were sent...");
            return -1;
        }
    }

    if ((bread = read(sockfd, incoming, sizeof(incoming))) < 0)
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
    }

    edhoc_init_finalize(&ctx);

    printf("[%d] Handshake successfully completed...\n", counter++);
    printf("[%d] Transcript hash 4:\n", counter++);
    print_bstr(ctx.th_4, COSE_DIGEST_LEN);

    return 0;
}

int main(void) {
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
