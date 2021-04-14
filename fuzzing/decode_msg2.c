#include <sys/stat.h>

#include "edhoc/edhoc.h"
#include "format.h"

int main(int argc, char **argv) {
    int ret;

    char *filename;
    FILE *fp;
    struct stat filestatus;
    int file_size;
    char *file_contents;

    if (argc != 2) {
        fprintf(stderr, "%s <file_json>\n", argv[0]);
        return 1;
    }
    filename = argv[1];

    if (stat(filename, &filestatus) != 0) {
        fprintf(stderr, "File %s not found\n", filename);
        return 1;
    }
    file_size = filestatus.st_size;
    file_contents = (char *) malloc(filestatus.st_size);
    if (file_contents == NULL) {
        fprintf(stderr, "Memory error: unable to allocate %d bytes\n", file_size);
        return 1;
    }

    fp = fopen(filename, "rt");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open %s\n", filename);
        fclose(fp);
        free(file_contents);
        return 1;
    }
    if (fread(file_contents, file_size, 1, fp) != 1) {
        fprintf(stderr, "Unable t read content of %s\n", filename);
        fclose(fp);
        free(file_contents);
        return 1;
    }
    fclose(fp);

    // ---------------------------------- //

    edhoc_msg2_t msg2;
    const cipher_suite_t *cipherSuite;

    cipherSuite = NULL;

    format_msg2_init(&msg2);

    cipherSuite = edhoc_cipher_suite_from_id(EDHOC_CIPHER_SUITE_0);
    format_msg2_decode(&msg2, NO_CORR, cipherSuite, (uint8_t *) file_contents, file_size);
    format_msg2_decode(&msg2, CORR_1_2, cipherSuite, (uint8_t *) file_contents, file_size);
    format_msg2_decode(&msg2, CORR_2_3, cipherSuite, (uint8_t *) file_contents, file_size);
    format_msg2_decode(&msg2, CORR_ALL, cipherSuite, (uint8_t *) file_contents, file_size);

    return 0;
}
