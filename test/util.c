#include <stdio.h>

#include "util.h"

int compare_arrays(const uint8_t a[], const uint8_t b[], int size) {
    for (int i = 0; i < size; i++) {
        if (a[i] != b[i]){
            fprintf(stderr, "Arrays are not equal at index: %d\n", i);
            return -1;
        }
    }
    return 0;
}
