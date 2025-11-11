/*
 * Advanced Encryption Standard
 * @author Dani Huertas
 * @email huertas.dani@gmail.com
 *
 * Based on the document FIPS PUB 197
 */
#include <stdio.h>
#include "aes.h"
#include <stdlib.h>
#include <string.h>
#define AES_BLOCK_SIZE 16

int main() {

    uint8_t i;
    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    const char *plaintext = "Ola, sou o AES!";
    
    uint8_t in[AES_BLOCK_SIZE];
    uint8_t out[AES_BLOCK_SIZE];
    uint8_t decrypted[AES_BLOCK_SIZE]; 

    strncpy((char *)in, plaintext, AES_BLOCK_SIZE);
    if (strlen(plaintext) < AES_BLOCK_SIZE) {
        memset(in + strlen(plaintext), 0, AES_BLOCK_SIZE - strlen(plaintext));
    }

    uint8_t *w; 

    w = aes_init(sizeof(key));
    aes_key_expansion(key, w);

    printf("📝 Mensagem de texto normal:\n");
    printf("%s\n", plaintext);

    printf("Input (Hex - antes do cipher):\n");
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x ", in[i]);
    }
    printf("\n\n");

    aes_cipher(in /* in */, out /* out */, w /* expanded key */);

    printf("Ciphered message (Hex):\n");
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x ", out[i]);
    }
    printf("\n\n");
    
    aes_inv_cipher(out, decrypted, w); 

    
    printf(" Original message (after inv cipher - HEX):\n");
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x ", decrypted[i]);
    }
    printf("\n");

    printf(" Original message (after inv cipher - TEXTO):\n");
    
    printf("%s\n", decrypted);
    
    printf("\n");

    free(w);

    return 0;
}