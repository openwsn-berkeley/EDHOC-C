#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "util.h"

void print_bstr(const uint8_t *bstr, size_t bstr_len) {
    for (int i = 0; i < bstr_len; i++) {
        if ((i + 1) % 10 == 0)
            printf("0x%02x \n", bstr[i]);
        else
            printf("0x%02x ", bstr[i]);
    }
    printf("\n");
}
