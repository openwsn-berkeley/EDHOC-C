#include "util.h"

bool compare_arrays(const uint8_t a[], const uint8_t b[], int size) {
    for (int i = 0; i < size; i++) {
        if (a[i] != b[i])
            return false;
    }
    return true;
}
