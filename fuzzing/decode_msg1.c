#include <sys/stat.h>

#include "edhoc/edhoc.h"
#include "format.h"

int main(int argc, char **argv) {
    int ret;

    char *filename;
    FILE *fp;
    struct stat fileStatus;
    int fileSize;
    char *contents;

    if (argc != 2) {
        fprintf(stderr, "%s <file name>\n", argv[0]);
        return 1;
    }
    filename = argv[1];

    if (stat(filename, &fileStatus) != 0) {
        fprintf(stderr, "File %s not found\n", filename);
        return 1;
    }
    fileSize = fileStatus.st_size;
    contents = (char *) malloc(fileStatus.st_size);
    if (contents == NULL) {
        fprintf(stderr, "Memory error: unable to allocate %d bytes\n", fileSize);
        return 1;
    }

    fp = fopen(filename, "rt");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open %s\n", filename);
        fclose(fp);
        free(contents);
        return 1;
    }
    if (fread(contents, fileSize, 1, fp) != 1) {
        fprintf(stderr, "Unable to read content of %s\n", filename);
        fclose(fp);
        free(contents);
        return 1;
    }
    fclose(fp);

    edhoc_msg1_t msg1;

    format_msg1_init(&msg1);
    ret = format_msg1_decode(&msg1, (uint8_t *) contents, fileSize);

    return ret;
}
