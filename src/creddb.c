#include <string.h>
#include "edhoc/creddb.h"

#define X509_DER_CERT_INIT_TV1 {                                            \
    0x58, 0x65, 0x54, 0x13, 0x20, 0x4c, 0x3e, 0xbc, 0x34, 0x28, 0xa6, 0xcf, \
    0x57, 0xe2, 0x4c, 0x9d, 0xef, 0x59, 0x65, 0x17, 0x70, 0x44, 0x9b, 0xce, \
    0x7e, 0xc6, 0x56, 0x1e, 0x52, 0x43, 0x3a, 0xa5, 0x5e, 0x71, 0xf1, 0xfa, \
    0x34, 0xb2, 0x2a, 0x9c, 0xa4, 0xa1, 0xe1, 0x29, 0x24, 0xea, 0xe1, 0xd1, \
    0x76, 0x60, 0x88, 0x09, 0x84, 0x49, 0xcb, 0x84, 0x8f, 0xfc, 0x79, 0x5f, \
    0x88, 0xaf, 0xc4, 0x9c, 0xbe, 0x8a, 0xfd, 0xd1, 0xba, 0x00, 0x9f, 0x21, \
    0x67, 0x5e, 0x8f, 0x6c, 0x77, 0xa4, 0xa2, 0xc3, 0x01, 0x95, 0x60, 0x1f, \
    0x6f, 0x0a, 0x08, 0x52, 0x97, 0x8b, 0xd4, 0x3d, 0x28, 0x20, 0x7d, 0x44, \
    0x48, 0x65, 0x02, 0xff, 0x7b, 0xdd, 0xa6                                \
    }

#define X509_DER_CERT_INIT_ID_TV1 {                                         \
    0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0x70, 0x5d, 0x58, 0x45, 0xf3, 0x6f, \
    0xc6, 0xa6                                                              \
}

#define X509_DER_CERT_INIT_ID_VALUE_TV1 {                                   \
    0x70, 0x5d, 0x58, 0x45, 0xf3, 0x6f, 0xc6, 0xa6                          \
}

#define X509_AUTH_KEY_INIT_TV1 {                                            \
    0xa4, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20, 0x38, 0xe5, 0xd5, 0x45, \
    0x63, 0xc2, 0xb6, 0xa4, 0xba, 0x26, 0xf3, 0x01, 0x5f, 0x61, 0xbb, 0x70, \
    0x6e, 0x5c, 0x2e, 0xfd, 0xb5, 0x56, 0xd2, 0xe1, 0x69, 0x0b, 0x97, 0xfc, \
    0x3c, 0x6d, 0xe1, 0x49, 0x23, 0x58, 0x20, 0x2f, 0xfc, 0xe7, 0xa0, 0xb2, \
    0xb8, 0x25, 0xd3, 0x97, 0xd0, 0xcb, 0x54, 0xf7, 0x46, 0xe3, 0xda, 0x3f, \
    0x27, 0x59, 0x6e, 0xe0, 0x6b, 0x53, 0x71, 0x48, 0x1d, 0xc0, 0xe0, 0x12, \
    0xbc, 0x34, 0xd7                                                        \
}

#define X509_DER_CERT_RESP_TV1 {                                            \
    0x58, 0x64, 0xc7, 0x88, 0x37, 0x00, 0x16, 0xb8, 0x96, 0x5b, 0xdb, 0x20, \
    0x74, 0xbf, 0xf8, 0x2e, 0x5a, 0x20, 0xe0, 0x9b, 0xec, 0x21, 0xf8, 0x40, \
    0x6e, 0x86, 0x44, 0x2b, 0x87, 0xec, 0x3f, 0xf2, 0x45, 0xb7, 0x0a, 0x47, \
    0x62, 0x4d, 0xc9, 0xcd, 0xc6, 0x82, 0x4b, 0x2a, 0x4c, 0x52, 0xe9, 0x5e, \
    0xc9, 0xd6, 0xb0, 0x53, 0x4b, 0x71, 0xc2, 0xb4, 0x9e, 0x4b, 0xf9, 0x03, \
    0x15, 0x00, 0xce, 0xe6, 0x86, 0x99, 0x79, 0xc2, 0x97, 0xbb, 0x5a, 0x8b, \
    0x38, 0x1e, 0x98, 0xdb, 0x71, 0x41, 0x08, 0x41, 0x5e, 0x5c, 0x50, 0xdb, \
    0x78, 0x97, 0x4c, 0x27, 0x15, 0x79, 0xb0, 0x16, 0x33, 0xa3, 0xef, 0x62, \
    0x71, 0xbe, 0x5c, 0x22, 0x5e, 0xb2                                      \
}

#define X509_DER_CERT_RESP_ID_TV1 {                                         \
    0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0x68, 0x44, 0x07, 0x8a, 0x53, 0xf3, \
    0x12, 0xf5                                                              \
}

#define X509_DER_CERT_RESP_ID_VALUE_TV1 {                                   \
    0x68, 0x44, 0x07, 0x8a, 0x53, 0xf3, 0x12, 0xf5                          \
}

#define X509_AUTH_KEY_RESP_TV1 {                                            \
    0xa4, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20, 0xdb, 0xd9, 0xdc, 0x8c, \
    0xd0, 0x3f, 0xb7, 0xc3, 0x91, 0x35, 0x11, 0x46, 0x2b, 0xb2, 0x38, 0x16, \
    0x47, 0x7c, 0x6b, 0xd8, 0xd6, 0x6e, 0xf5, 0xa1, 0xa0, 0x70, 0xac, 0x85, \
    0x4e, 0xd7, 0x3f, 0xd2, 0x23, 0x58, 0x20, 0xdf, 0x69, 0x27, 0x4d, 0x71, \
    0x32, 0x96, 0xe2, 0x46, 0x30, 0x63, 0x65, 0x37, 0x2b, 0x46, 0x83, 0xce, \
    0xd5, 0x38, 0x1b, 0xfc, 0xad, 0xcd, 0x44, 0x0a, 0x24, 0xc3, 0x91, 0xd2, \
    0xfe, 0xdb, 0x94                                                        \
}

#define RPK_CBOR_INIT_TV2 {                                                 \
    0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x2c, 0x44, 0x0c, 0xc1, \
    0x21, 0xf8, 0xd7, 0xf2, 0x4c, 0x3b, 0x0e, 0x41, 0xae, 0xda, 0xfe, 0x9c, \
    0xaa, 0x4f, 0x4e, 0x7a, 0xbb, 0x83, 0x5e, 0xc3, 0x0f, 0x1d, 0xe8, 0x8a, \
    0xdb, 0x96, 0xff, 0x71, 0x6c, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, \
    0x20, 0x6e, 0x61, 0x6d, 0x65, 0x60                                      \
}

#define RPK_CBOR_INIT_ID_TV2 {                                              \
    0xa1, 0x04, 0x41, 0x23                                                  \
}

#define RPK_CBOR_INIT_ID_VALUE_TV2 {                                        \
    0x23                                                                    \
}

#define RPK_AUTH_KEY_INIT_TV2 {                                             \
    0xa4, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20, 0x2c, 0x44, 0x0c, 0xc1, \
    0x21, 0xf8, 0xd7, 0xf2, 0x4c, 0x3b, 0x0e, 0x41, 0xae, 0xda, 0xfe, 0x9c, \
    0xaa, 0x4f, 0x4e, 0x7a, 0xbb, 0x83, 0x5e, 0xc3, 0x0f, 0x1d, 0xe8, 0x8a, \
    0xdb, 0x96, 0xff, 0x71, 0x23, 0x58, 0x20, 0x2b, 0xbe, 0xa6, 0x55, 0xc2, \
    0x33, 0x71, 0xc3, 0x29, 0xcf, 0xbd, 0x3b, 0x1f, 0x02, 0xc6, 0xc0, 0x62, \
    0x03, 0x38, 0x37, 0xb8, 0xb5, 0x90, 0x99, 0xa4, 0x43, 0x6f, 0x66, 0x60, \
    0x81, 0xb0, 0x8e                                                        \
}

#define RPK_CBOR_RESP_TV2 {                                                 \
    0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0xa3, 0xff, 0x26, 0x35, \
    0x95, 0xbe, 0xb3, 0x77, 0xd1, 0xa0, 0xce, 0x1d, 0x04, 0xda, 0xd2, 0xd4, \
    0x09, 0x66, 0xac, 0x6b, 0xcb, 0x62, 0x20, 0x51, 0xb8, 0x46, 0x59, 0x18, \
    0x4d, 0x5d, 0x9a, 0x32, 0x6c, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, \
    0x20, 0x6e, 0x61, 0x6d, 0x65, 0x60                                      \
}

#define RPK_CBOR_RESP_ID_TV2 {                                              \
    0xa1, 0x04, 0x41, 0x05                                                  \
}

#define RPK_CBOR_RESP_ID_VALUE_TV2 {                                        \
    0x05                                                                    \
}

#define RPK_AUTH_KEY_RESP_TV2 {                                             \
    0xa4, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20, 0xa3, 0xff, 0x26, 0x35, \
    0x95, 0xbe, 0xb3, 0x77, 0xd1, 0xa0, 0xce, 0x1d, 0x04, 0xda, 0xd2, 0xd4, \
    0x09, 0x66, 0xac, 0x6b, 0xcb, 0x62, 0x20, 0x51, 0xb8, 0x46, 0x59, 0x18, \
    0x4d, 0x5d, 0x9a, 0x32, 0x23, 0x58, 0x20, 0xbb, 0x50, 0x1a, 0xac, 0x67, \
    0xb9, 0xa9, 0x5f, 0x97, 0xe0, 0xed, 0xed, 0x6b, 0x82, 0xa6, 0x62, 0x93, \
    0x4f, 0xbb, 0xfc, 0x7a, 0xd1, 0xb7, 0x4c, 0x1f, 0xca, 0xd6, 0x6a, 0x07, \
    0x94, 0x22, 0xd0                                                        \
}

#define X509_DER_CERT_INIT_TV3 {                                            \
    0x58, 0x70, 0xf9, 0x9e, 0x91, 0x3e, 0x1b, 0x8d, 0x0a, 0x48, 0xde, 0xdd, \
    0x8e, 0x9d, 0x7a, 0x77, 0xb7, 0x81, 0xf3, 0xe0, 0x43, 0xc8, 0x9a, 0xb0, \
    0xba, 0xeb, 0xd8, 0x46, 0x51, 0x5b, 0x27, 0xba, 0x0f, 0x15, 0x61, 0x13, \
    0x2e, 0x77, 0x3d, 0xba, 0xc4, 0x52, 0x16, 0x2f, 0xa3, 0x40, 0xef, 0xfb, \
    0x7d, 0x38, 0xb5, 0xe6, 0x4c, 0x5f, 0xc3, 0x69, 0xf0, 0x21, 0xac, 0x66, \
    0x1a, 0x81, 0x34, 0x17, 0x6a, 0xad, 0x9f, 0x45, 0xd4, 0xd6, 0x2f, 0xba, \
    0x48, 0x3e, 0xe8, 0xf8, 0x92, 0x93, 0x96, 0x2b, 0x7f, 0x7b, 0x11, 0x5d, \
    0x41, 0x70, 0xc0, 0xe9, 0x14, 0xce, 0x5c, 0x32, 0x22, 0x2a, 0xf6, 0x94, \
    0xa4, 0xe6, 0x3c, 0x9b, 0x4b, 0x02, 0xf8, 0x73, 0xde, 0x35, 0xd9, 0xa0, \
    0x24, 0x3d, 0x76, 0xef, 0x04, 0x73                                      \
}

#define X509_DER_CERT_INIT_ID_TV3 {                                         \
    0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xd6, 0xfe, 0xbe, 0x26, 0x6e, 0x07, \
    0x4e, 0x63                                                              \
}

#define X509_DER_CERT_INIT_ID_VALUE_TV3 {                                   \
    0xd6, 0xfe, 0xbe, 0x26, 0x6e, 0x07, 0x4e, 0x63                          \
}

#define X509_AUTH_KEY_INIT_TV3 {                                            \
    0xa4, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20, 0x82, 0x9e, 0xbf, 0x2b, \
    0xfb, 0x95, 0x2e, 0x38, 0xa0, 0x49, 0x19, 0x7f, 0x6d, 0xc3, 0xa3, 0xee, \
    0xe0, 0x9d, 0xc5, 0x86, 0x40, 0x6b, 0xb6, 0xc5, 0x51, 0x3f, 0x31, 0x0b, \
    0xe4, 0x01, 0x7a, 0xeb, 0x23, 0x58, 0x20, 0xc0, 0xd9, 0x27, 0xdf, 0x7f, \
    0x35, 0x82, 0xc0, 0x49, 0xd2, 0xf9, 0xb5, 0x9a, 0x8c, 0x02, 0x2e, 0xb7, \
    0xe5, 0x2f, 0x43, 0xe3, 0x60, 0x02, 0x3d, 0xd4, 0x2a, 0x04, 0x58, 0x68, \
    0xff, 0x11, 0xc7                                                        \
}

#define RPK_CBOR_RESP_TV3 {                                                 \
    0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x29, 0x95, 0x17, 0x19, \
    0x52, 0x2e, 0xf4, 0x32, 0x01, 0xbe, 0x13, 0x3e, 0x48, 0x8f, 0xe9, 0x21, \
    0xd8, 0xbb, 0x5b, 0x4f, 0x14, 0xee, 0xa0, 0xb9, 0x7b, 0xce, 0x60, 0x59, \
    0x34, 0xbe, 0x15, 0x62, 0x6c, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, \
    0x20, 0x6e, 0x61, 0x6d, 0x65, 0x60                                      \
}

#define RPK_CBOR_RESP_ID_TV3 {                                              \
    0xa1, 0x04, 0x41, 0x20                                                  \
}

#define RPK_CBOR_RESP_ID_VALUE_TV3 {                                        \
    0x20                                                                    \
}

#define RPK_AUTH_KEY_RESP_TV3   { \
    0xa4, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20, 0x29, 0x95, 0x17, 0x19, \
    0x52, 0x2e, 0xf4, 0x32, 0x01, 0xbe, 0x13, 0x3e, 0x48, 0x8f, 0xe9, 0x21, \
    0xd8, 0xbb, 0x5b, 0x4f, 0x14, 0xee, 0xa0, 0xb9, 0x7b, 0xce, 0x60, 0x59, \
    0x34, 0xbe, 0x15, 0x62, 0x23, 0x58, 0x20, 0xb9, 0x2d, 0x7f, 0x67, 0x94, \
    0x42, 0xff, 0xd7, 0x43, 0xf7, 0xea, 0x05, 0xd5, 0x4c, 0x67, 0x47, 0x7e, \
    0x4a, 0xe4, 0x87, 0xf8, 0xc0, 0x86, 0xb9, 0x86, 0xe0, 0xa3, 0xc1, 0xbd, \
    0x49, 0x11, 0x58                                                        \
}

#define RPK_CBOR_INIT_TV4 {                                                 \
    0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0xa4, 0x05, 0xc0, 0xce, \
    0x61, 0x5a, 0xcd, 0x26, 0x60, 0x70, 0x94, 0xc2, 0x4b, 0x5a, 0x83, 0x7a, \
    0xbb, 0xb0, 0xf1, 0x2c, 0xa7, 0x8d, 0x5c, 0xcf, 0xa2, 0x6d, 0x88, 0x4e, \
    0x1c, 0x22, 0x4b, 0x54, 0x6c, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, \
    0x20, 0x6e, 0x61, 0x6d, 0x65, 0x60                                      \
}

#define RPK_CBOR_INIT_ID_TV4 {                                              \
    0xa1, 0x04, 0x41, 0x20                                                  \
}

#define RPK_CBOR_INIT_ID_VALUE_TV4 {                                        \
    0x20                                                                    \
}

#define RPK_AUTH_KEY_INIT_TV4 {                                             \
    0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0xa4, 0x05, 0xc0, 0xce, \
    0x61, 0x5a, 0xcd, 0x26, 0x60, 0x70, 0x94, 0xc2, 0x4b, 0x5a, 0x83, 0x7a, \
    0xbb, 0xb0, 0xf1, 0x2c, 0xa7, 0x8d, 0x5c, 0xcf, 0xa2, 0x6d, 0x88, 0x4e, \
    0x1c, 0x22, 0x4b, 0x54, 0x23, 0x58, 0x20, 0xb8, 0xac, 0x7d, 0xe8, 0x2b, \
    0xb7, 0x6c, 0xd6, 0xd0, 0xa1, 0x88, 0x27, 0x50, 0x27, 0x6e, 0xe7, 0x41, \
    0x63, 0x4d, 0xa2, 0xe9, 0x15, 0x66, 0xab, 0xbe, 0xc1, 0xdf, 0x71, 0xc8, \
    0x64, 0x07, 0xca                                                        \
}

#define X509_DER_CERT_RESP_TV4 {                                            \
    0x58, 0x75, 0xc0, 0x03, 0x66, 0x25, 0xe3, 0xa8, 0x88, 0xce, 0xfe, 0x5a, \
    0xb1, 0xda, 0x82, 0x10, 0x08, 0xa5, 0xef, 0x99, 0x35, 0x08, 0x4b, 0x3b, \
    0x73, 0x20, 0xcd, 0x9b, 0xe6, 0x51, 0xd9, 0xdc, 0x30, 0x8a, 0x31, 0x0b, \
    0x3f, 0xca, 0x69, 0xbb, 0x68, 0xe3, 0x9b, 0xec, 0xba, 0x7e, 0x5d, 0x32, \
    0x8c, 0x5f, 0xf0, 0x13, 0x59, 0xea, 0xba, 0xb0, 0xce, 0xe6, 0xf6, 0xa8, \
    0x20, 0x82, 0xab, 0x39, 0xa3, 0x95, 0xda, 0xa8, 0x99, 0x2a, 0xfc, 0xe3, \
    0x47, 0x3c, 0xac, 0x66, 0x4f, 0xbe, 0xa0, 0x5b, 0x39, 0xdf, 0xdd, 0x05, \
    0x53, 0x8b, 0x2b, 0x5e, 0xbb, 0x35, 0xc7, 0xff, 0xba, 0xd4, 0x59, 0x41, \
    0x53, 0x2b, 0x25, 0xa2, 0x1c, 0x4e, 0x85, 0x6a, 0x4d, 0x62, 0x97, 0x8e, \
    0x17, 0xa4, 0x33, 0xd4, 0x37, 0xad, 0x20, 0x38, 0xca, 0xf4, 0x87        \
}

#define X509_DER_CERT_RESP_ID_TV4 {                                         \
   0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xf4, 0x9c, 0xc8, 0x74, 0x6e, 0x4c,  \
   0xca, 0x60                                                               \
}

#define X509_DER_CERT_RESP_ID_VALUE_TV4 {                                   \
    0xf4, 0x9c, 0xc8, 0x74, 0x6e, 0x4c, 0xca, 0x60                          \
}

#define X509_AUTH_KEY_RESP_TV4 {                                            \
    0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x3c, 0x85, 0xb5, 0x7c, \
    0xc5, 0x1b, 0xa1, 0x93, 0x1e, 0xa7, 0x3a, 0x58, 0xa6, 0xac, 0x93, 0x39, \
    0x04, 0xd2, 0xd8, 0x91, 0x30, 0x97, 0xf6, 0x52, 0x55, 0xca, 0xd2, 0x5a, \
    0xf0, 0xd6, 0xc9, 0x91, 0x23, 0x58, 0x20, 0x7b, 0xff, 0xb0, 0x55, 0xe9, \
    0x92, 0x9a, 0xed, 0x63, 0xa4, 0x23, 0x50, 0x7c, 0xc9, 0xa1, 0x4c, 0x64, \
    0xc5, 0xd9, 0x66, 0x16, 0xf1, 0xcd, 0x63, 0xd2, 0xe0, 0xd5, 0x0d, 0xce, \
    0x41, 0xf1, 0x33                                                        \
}

#define RPK_CBOR_CHRISTIAN { \
    0xa3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20, 0x4a, 0x26, 0xdd, 0x69, \
    0xe9, 0x93, 0xbe, 0xc5, 0x9a, 0xb7, 0xbf, 0x47, 0x29, 0x09, 0x1f, 0x1e, \
    0x25, 0x16, 0xb9, 0xac, 0xed, 0xfe, 0x9d, 0xcc, 0x58, 0x8c, 0xa1, 0xaf, \
    0x82, 0x50, 0x6c, 0x54                                                  \
}

#define RPK_CBOR_CHRISTAIN_ID { \
    0xa1, 0x04, 0x49, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x52, 0x50, 0x4b  \
}

#define RPK_CBOR_CHRISTIAN_ID_VALUE { \
    0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x52, 0x50, 0x4b  \
}

#define X509_DER_CERT_EDDSA_EXT_TV1 {                                       \
    0x58, 0xb0, 0x30, 0x82, 0x01, 0x08, 0x30, 0x81, 0xbb, 0x02, 0x14, 0x53, \
    0xdf, 0x1f, 0x15, 0x7f, 0x13, 0x29, 0xfd, 0x00, 0x51, 0xb4, 0x06, 0x32, \
    0x35, 0x25, 0xf3, 0x37, 0xb8, 0x87, 0x8f, 0x30, 0x05, 0x06, 0x03, 0x2b, \
    0x65, 0x70, 0x30, 0x27, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, \
    0x06, 0x13, 0x02, 0x42, 0x45, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, \
    0x04, 0x03, 0x0c, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x6f, 0x70, 0x65, 0x6e, \
    0x77, 0x73, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x30, 0x1e, 0x17, 0x0d, 0x32, \
    0x31, 0x30, 0x34, 0x31, 0x34, 0x30, 0x37, 0x31, 0x39, 0x34, 0x37, 0x5a, \
    0x17, 0x0d, 0x32, 0x33, 0x30, 0x33, 0x31, 0x35, 0x30, 0x37, 0x31, 0x39, \
    0x34, 0x37, 0x5a, 0x30, 0x27, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, \
    0x04, 0x06, 0x13, 0x02, 0x42, 0x45, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, \
    0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x6f, 0x70, 0x65, \
    0x6e, 0x77, 0x73, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x30, 0x2a, 0x30, 0x05, \
    0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xcc, 0x03, 0xac, 0xc4, \
    0x0e, 0xd7, 0xa0, 0xa8, 0xf9, 0x0f, 0x38, 0x17, 0x37, 0x0a              \
}

#define X509_AUTH_KEY_EXT_TV1 {                                             \
    0xa3, 0x01, 0x01, 0x20, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, \
    0x23, 0x58, 0x20, 0x81, 0xfd, 0xa3, 0x87, 0xdb, 0x99, 0xeb, 0x5f, 0x00, \
    0xd6, 0xa6, 0xf4, 0x7f, 0x2d, 0x3c, 0x1b, 0xfc, 0x43, 0xd2, 0x2d, 0xb6, \
    0x95, 0xdd, 0x13, 0x17, 0x10, 0xb5, 0x05, 0xe4, 0x1a, 0x51, 0x6f        \
}

#define X509_DER_CERT_EDDSA_ID_EXT_TV1 {                                    \
    0xa1, 0x18, 0x23, 0x82, 0x2e, 0x48, 0xca, 0x48, 0xfd, 0xc2, 0x51, 0x32, \
    0x62, 0xba                                                              \
};

const uint8_t x509_der_cert_init_tv1[] = X509_DER_CERT_INIT_TV1;
const uint8_t x509_der_cert_init_id_tv1[] = X509_DER_CERT_INIT_ID_TV1;
const uint8_t x509_der_cert_init_id_value_tv1[] = X509_DER_CERT_INIT_ID_VALUE_TV1;
const uint8_t x509_auth_key_init_tv1[] = X509_AUTH_KEY_INIT_TV1;
const uint8_t x509_der_cert_resp_tv1[] = X509_DER_CERT_RESP_TV1;
const uint8_t x509_der_cert_resp_id_tv1[] = X509_DER_CERT_RESP_ID_TV1;
const uint8_t x509_der_cert_resp_id_value_tv1[] = X509_DER_CERT_RESP_ID_VALUE_TV1;
const uint8_t x509_auth_key_resp_tv1[] = X509_AUTH_KEY_RESP_TV1;

const uint8_t rpk_cbor_init_tv2[] = RPK_CBOR_INIT_TV2;
const uint8_t rpk_cbor_init_id_tv2[] = RPK_CBOR_INIT_ID_TV2;
const uint8_t rpk_cbor_init_id_value_tv2[] = RPK_CBOR_INIT_ID_VALUE_TV2;
const uint8_t rpk_auth_key_init_tv2[] = RPK_AUTH_KEY_INIT_TV2;
const uint8_t rpk_cbor_resp_tv2[] = RPK_CBOR_RESP_TV2;
const uint8_t rpk_cbor_resp_id_tv2[] = RPK_CBOR_RESP_ID_TV2;
const uint8_t rpk_cbor_resp_id_value_tv2[] = RPK_CBOR_RESP_ID_VALUE_TV2;
const uint8_t rpk_auth_key_resp_tv2[] = RPK_AUTH_KEY_RESP_TV2;

const uint8_t x509_der_cert_init_tv3[] = X509_DER_CERT_INIT_TV3;
const uint8_t x509_der_cert_init_id_tv3[] = X509_DER_CERT_INIT_ID_TV3;
const uint8_t x509_der_cert_init_id_value_tv3[] = X509_DER_CERT_INIT_ID_VALUE_TV3;
const uint8_t x509_auth_key_init_tv3[] = X509_AUTH_KEY_INIT_TV3;
const uint8_t rpk_cbor_resp_tv3[] = RPK_CBOR_RESP_TV3;
const uint8_t rpk_cbor_resp_id_tv3[] = RPK_CBOR_RESP_ID_TV3;
const uint8_t rpk_cbor_resp_id_value_tv3[] = RPK_CBOR_RESP_ID_VALUE_TV3;
const uint8_t rpk_auth_key_resp_tv3[] = RPK_AUTH_KEY_RESP_TV3;

const uint8_t rpk_cbor_init_tv4[] = RPK_CBOR_INIT_TV4;
const uint8_t rpk_cbor_init_id_tv4[] = RPK_CBOR_INIT_ID_TV4;
const uint8_t rpk_cbor_init_id_value_tv4[] = RPK_CBOR_INIT_ID_VALUE_TV4;
const uint8_t rpk_auth_key_init_tv4[] = RPK_AUTH_KEY_INIT_TV4;
const uint8_t x509_der_cert_resp_tv4[] = X509_DER_CERT_RESP_TV4;
const uint8_t x509_der_cert_resp_id_tv4[] = X509_DER_CERT_RESP_ID_TV4;
const uint8_t x509_der_cert_resp_id_value_tv4[] = X509_DER_CERT_RESP_ID_VALUE_TV4;
const uint8_t x509_auth_key_resp_tv4[] = X509_AUTH_KEY_RESP_TV4;

typedef struct cred_db_t cred_db_t;

struct cred_db_t {
    cred_type_t credType;
    const uint8_t *id;
    size_t idLen;
    const uint8_t *authKey;
    size_t authKeyLen;
    const uint8_t *credValue;
    size_t credValueLen;
};

cred_db_t credDb[] = {
        {
                CRED_TYPE_DER_CERT,
                x509_der_cert_init_id_value_tv1,
                sizeof(x509_der_cert_init_id_value_tv1),
                x509_auth_key_init_tv1,
                sizeof(x509_auth_key_init_tv1),
                x509_der_cert_init_tv1,
                sizeof(x509_der_cert_init_tv1)
        },
        {
                CRED_TYPE_DER_CERT,
                x509_der_cert_resp_id_value_tv1,
                sizeof(x509_der_cert_resp_id_value_tv1),
                x509_auth_key_resp_tv1,
                sizeof(x509_auth_key_resp_tv1),
                x509_der_cert_resp_tv1,
                sizeof(x509_der_cert_resp_tv1)
        },
        {
                CRED_TYPE_RPK,
                rpk_cbor_init_id_value_tv2,
                sizeof(rpk_cbor_init_id_value_tv2),
                rpk_auth_key_init_tv2,
                sizeof(rpk_auth_key_init_tv2),
                rpk_cbor_init_tv2,
                sizeof(rpk_cbor_init_tv2),
        },
        {
                CRED_TYPE_RPK,
                rpk_cbor_resp_id_value_tv2,
                sizeof(rpk_cbor_resp_id_value_tv2),
                rpk_auth_key_resp_tv2,
                sizeof(rpk_auth_key_resp_tv2),
                rpk_cbor_resp_tv2,
                sizeof(rpk_cbor_resp_tv2),
        },
        {
                CRED_TYPE_DER_CERT,
                x509_der_cert_init_id_value_tv3,
                sizeof(x509_der_cert_init_id_value_tv3),
                x509_auth_key_init_tv3,
                sizeof(x509_auth_key_init_tv3),
                x509_der_cert_init_tv3,
                sizeof(x509_der_cert_init_tv3)
        },
        {
                CRED_TYPE_RPK,
                rpk_cbor_resp_id_value_tv3,
                sizeof(rpk_cbor_resp_id_value_tv3),
                rpk_auth_key_resp_tv3,
                sizeof(rpk_auth_key_resp_tv3),
                rpk_cbor_resp_tv3,
                sizeof(rpk_cbor_resp_tv3),
        },
        {
                CRED_TYPE_RPK,
                rpk_cbor_init_id_value_tv4,
                sizeof(rpk_cbor_init_id_value_tv4),
                rpk_auth_key_init_tv4,
                sizeof(rpk_auth_key_init_tv4),
                rpk_cbor_init_tv4,
                sizeof(rpk_cbor_init_tv4),
        },
        {
                CRED_TYPE_DER_CERT,
                x509_der_cert_resp_id_value_tv4,
                sizeof(x509_der_cert_resp_id_value_tv4),
                x509_auth_key_resp_tv4,
                sizeof(x509_auth_key_resp_tv4),
                x509_der_cert_resp_tv4,
                sizeof(x509_der_cert_resp_tv4)
        }

};


int f_remote_creds(const uint8_t *key, size_t keyLen, cred_type_t* credType, const uint8_t **cred, size_t *credLen, const uint8_t **authKey, size_t* authKeyLen) {
    int ret, i;

    for (i = 0; i < (int) (sizeof(credDb) / sizeof(cred_db_t)); i++) {
        if (credDb[i].idLen == keyLen && memcmp(credDb[i].id, key, keyLen) == 0) {
            *credType = credDb[i].credType;
            *cred = credDb[i].credValue;
            *credLen = credDb[i].credValueLen;
            *authKey = credDb[i].authKey;
            *authKeyLen = credDb[i].authKeyLen;
            break;
        }
    }

    if (i == sizeof(credDb) / sizeof(cred_db_t)) {
        cred = NULL;
        *credLen = 0;
        authKey = NULL;
        *authKeyLen = 0;
        ret = EDHOC_ERR_INVALID_CRED_ID;
    } else {
        ret = 0;
    }

    return ret;
}
