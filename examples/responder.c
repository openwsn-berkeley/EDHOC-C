#include <edhoc/edhoc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

#define PORT 9830

// #define IPV6

int counter = 1;

const uint8_t auth_key[] = {0xa4, 0x01, 0x01, 0x20, 0x06, 0x23, 0x58, 0x20, 0xdf, 0x69, 0x27, 0x4d, 0x71, 0x32, 0x96,
                            0xe2, 0x46, 0x30, 0x63, 0x65, 0x37, 0x2b, 0x46, 0x83, 0xce, 0xd5, 0x38, 0x1b, 0xfc, 0xad,
                            0xcd, 0x44, 0xa, 0x24, 0xc3, 0x91, 0xd2, 0xfe, 0xdb, 0x94, 0x4, 0x80};


const uint8_t cbor_cert[] = {0x58, 0x6e, 0x47, 0x62, 0x4d, 0xc9, 0xcd, 0xc6, 0x82, 0x4b, 0x2a, 0x4c, 0x52, 0xe9, 0x5e,
                             0xc9, 0xd6, 0xb0, 0x53, 0x4b, 0x71, 0xc2, 0xb4, 0x9e, 0x4b, 0xf9, 0x03, 0x15, 0x00, 0xce,
                             0xe6, 0x86, 0x99, 0x79, 0xc2, 0x97, 0xbb, 0x5a, 0x8b, 0x38, 0x1e, 0x98, 0xdb, 0x71, 0x41,
                             0x08, 0x41, 0x5e, 0x5c, 0x50, 0xdb, 0x78, 0x97, 0x4c, 0x27, 0x15, 0x79, 0xb0, 0x16, 0x33,
                             0xa3, 0xef, 0x62, 0x71, 0xbe, 0x5c, 0x22, 0x5e, 0xb2, 0x8f, 0x9c, 0xf6, 0x18, 0x0b, 0x5a,
                             0x6a, 0xf3, 0x1e, 0x80, 0x20, 0x9a, 0x08, 0x5c, 0xfb, 0xf9, 0x5f, 0x3f, 0xdc, 0xf9, 0xb1,
                             0x8b, 0x69, 0x3d, 0x6c, 0x0e, 0x0d, 0x0f, 0xfb, 0x8e, 0x3f, 0x9a, 0x32, 0xa5, 0x08, 0x59,
                             0xec, 0xd0, 0xbf, 0xcf, 0xf2, 0xc2, 0x18};

const uint8_t cid[] = {0x2b};

const uint8_t eph_key[] = {0xa5, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x71, 0xa3, 0xd5, 0x99, 0xc2, 0x1d, 0xa1,
                           0x89, 0x02, 0xa1, 0xae, 0xa8, 0x10, 0xb2, 0xb6, 0x38, 0x2c, 0xcd, 0x8d, 0x5f, 0x9b, 0xf0,
                           0x19, 0x52, 0x81, 0x75, 0x4c, 0x5e, 0xbc, 0xaf, 0x30, 0x1e, 0x23, 0x58, 0x20, 0xfd, 0x8c,
                           0xd8, 0x77, 0xc9, 0xea, 0x38, 0x6e, 0x6a, 0xf3, 0x4f, 0xf7, 0xe6, 0x06, 0xc4, 0xb6, 0x4c,
                           0xa8, 0x31, 0xc8, 0xba, 0x33, 0x13, 0x4f, 0xd4, 0xcd, 0x71, 0x67, 0xca, 0xba, 0xec, 0xda,
                           0x04, 0x80};

const uint8_t cred_id[] = {0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xfc, 0x79, 0x99, 0x0f, 0x24, 0x31, 0xa3, 0xf5};

void print_bstr(const uint8_t *bstr, size_t bstr_len) {
    for (int i = 0; i < bstr_len; i++) {
        if ((i + 1) % 10 == 0)
            printf("0x%02x \n", bstr[i]);
        else
            printf("0x%02x ", bstr[i]);
    }
    printf("\n");
}

int edhoc_handshake(int sockfd, bool epk) {
    ssize_t bread, len, written;
    uint8_t incoming[500], outgoing[500];

    cbor_cert_t cert;
    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    printf("[%d] Set up EDHOC configuration...\n", counter++);
    if (edhoc_conf_setup(&conf, EDHOC_IS_RESPONDER, NULL, NULL, NULL) != 0)
        return -1;

    edhoc_cred_cbor_cert_init(&cert);
    if (edhoc_cred_load_cbor_cert(&cert, cbor_cert, sizeof(cbor_cert)) != 0)
        return -1;

    printf("[%d] Load private authentication key...\n", counter++);
    edhoc_conf_load_authkey(&conf, auth_key, sizeof(auth_key));

    printf("[%d] Load CBOR certificate...\n", counter++);
    edhoc_conf_load_credentials(&conf, CRED_TYPE_CBOR_CERT, &cert, NULL);

    printf("[%d] Compute and load CBOR certificate hash:\n", counter++);
    print_bstr(cred_id, sizeof(cred_id));

    if (edhoc_conf_load_cred_id(&conf, cred_id, CRED_ID_TYPE_X5T, sizeof(cred_id)) != 0)
        return -1;

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf);

    if (!epk){
        if (edhoc_load_ephkey(&ctx, eph_key, sizeof(eph_key)) != 0)
            return -1;
    }

    if (edhoc_session_preset_cidr(&ctx, cid, sizeof(cid)) != 0)
        return -1;

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

    printf("[%d] Received a message (%ld bytes):\n", counter++, bread);
    print_bstr(incoming, bread);

    edhoc_resp_finalize(&ctx, incoming, bread);

    printf("[%d] Handshake successfully completed...\n", counter++);
    printf("[%d] Transcript hash 4:\n", counter++);
    print_bstr(ctx.session.th_4, EDHOC_HASH_MAX_SIZE);

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


int main(int argc, char** argv) {
    ssize_t ret;
    ssize_t errc;
    bool epk = false;

    int sockfd, connfd;
    socklen_t client_addr_len;
#if defined(IPV6)
    struct sockaddr_in6 servaddr, cli;
#else
    struct sockaddr_in servaddr, cli;
#endif

    ret = -1;

    if (argc == 2){
        if (strcmp(argv[1], "--epk") == 0){
            epk = true;
        } else {
            epk = false;
        }
    }

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

    edhoc_handshake(connfd, epk);

    printf("[%d] Closing socket...\n", counter++);
    close(sockfd);

    ret = 0;
    exit:
    return ret;
}