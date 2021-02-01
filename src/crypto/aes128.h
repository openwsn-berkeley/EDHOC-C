/**************************************************************
AES128
Author:   Uli Kretzschmar
MSP430 Systems
Freising
AES software support for encryption and decryption
ECCN 5D002 TSU - Technology / Software Unrestricted
Source: http://is.gd/o9RSPq
**************************************************************/

#ifndef EDHOC_HACL_AES128_H
#define EDHOC_HACL_AES128_H

#include "edhoc/edhoc.h"

//=========================== prototypes ======================================

/**
 * @brief Basic AES encryption of a single 16-octet block.
 *
 * @param[in,out] buffer Single block plaintext. Will be overwritten by ciphertext.
 * @param[in] key Buffer containing the secret key (16 octets).
 *
 * @returns E_SUCCESS when the encryption was successful.
 */
int aes128_enc(uint8_t *buffer, uint8_t *key);

#endif /* EDHOC_HACL_AES128_H */
