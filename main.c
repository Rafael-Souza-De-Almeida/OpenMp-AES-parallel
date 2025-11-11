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

size_t pkcs7_pad(uint8_t *data, size_t data_len) {
    uint8_t padding_len = AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE);
    size_t new_len = data_len + padding_len;
    for (size_t i = 0; i < padding_len; i++) {
        data[data_len + i] = padding_len;
    }
    return new_len;
}

size_t pkcs7_unpad(uint8_t *data, size_t data_len) {
    if (data_len == 0 || (data_len % AES_BLOCK_SIZE) != 0) return data_len;
    uint8_t padding_len = data[data_len - 1];
    if (padding_len == 0 || padding_len > AES_BLOCK_SIZE || padding_len > data_len) {
        return data_len;
    }
    return data_len - padding_len;
}

void aes_encrypt_cbc(const char *input_filename, const char *output_filename, uint8_t *key, size_t key_size) {
    
    FILE *fin, *fout;
    
    uint8_t iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    }; 
    uint8_t block[AES_BLOCK_SIZE]; 
    uint8_t prev_cipher_block[AES_BLOCK_SIZE]; // C(i-1) ou IV
    uint8_t ciphered_block[AES_BLOCK_SIZE]; // C(i)
    
    
    uint8_t *w = aes_init(key_size);
    if (!w) { perror("Erro de alocação de chave"); return; }
    aes_key_expansion(key, w);

    
    fin = fopen(input_filename, "rb");
    fout = fopen(output_filename, "wb");
    if (!fin || !fout) {
        perror("Erro ao abrir arquivo");
        free(w);
        return;
    }

    
    fwrite(iv, 1, AES_BLOCK_SIZE, fout); 
    memcpy(prev_cipher_block, iv, AES_BLOCK_SIZE);

    size_t bytes_read;
    
   
    while (1) {
        
        bytes_read = fread(block, 1, AES_BLOCK_SIZE, fin);
        
        
        int is_last_chunk = feof(fin);
        
        
        if (bytes_read == 0 && !is_last_chunk) break;
        
        size_t current_len = bytes_read;
        
        
        if (is_last_chunk || bytes_read < AES_BLOCK_SIZE) {
            
            current_len = pkcs7_pad(block, bytes_read);
        }

       
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            block[i] ^= prev_cipher_block[i];
        }

        
        aes_cipher(block, ciphered_block, w); 

        
        fwrite(ciphered_block, 1, AES_BLOCK_SIZE, fout);

        
        memcpy(prev_cipher_block, ciphered_block, AES_BLOCK_SIZE);
        
        
        if (is_last_chunk || bytes_read < AES_BLOCK_SIZE) break;
    }
    
    printf("✅ Criptografia de '%s' para '%s' (CBC) concluída.\n", input_filename, output_filename);

    
    fclose(fin);
    fclose(fout);
    free(w);
}

void aes_decrypt_cbc(const char *input_filename, const char *output_filename, uint8_t *key, size_t key_size) {
    
    FILE *fin, *fout;
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t cipher_block[AES_BLOCK_SIZE];      
    uint8_t prev_cipher_block[AES_BLOCK_SIZE]; 
    uint8_t decrypted_block[AES_BLOCK_SIZE];   
    uint8_t final_plaintext_block[AES_BLOCK_SIZE]; 

    uint8_t *w = aes_init(key_size);
    if (!w) { perror("Erro de alocação de chave"); return; }
    aes_key_expansion(key, w);

    fin = fopen(input_filename, "rb");
    fout = fopen(output_filename, "wb");
    if (!fin || !fout) {
        perror("Erro ao abrir arquivo");
        free(w);
        return;
    }
    
   
    if (fread(iv, 1, AES_BLOCK_SIZE, fin) != AES_BLOCK_SIZE) {
        fprintf(stderr, "Erro: Arquivo cifrado muito pequeno ou inválido (falta o IV).\n");
        fclose(fin); fclose(fout); free(w); return;
    }
    
    
    memcpy(prev_cipher_block, iv, AES_BLOCK_SIZE);

    
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin) - AES_BLOCK_SIZE; 
    fseek(fin, AES_BLOCK_SIZE, SEEK_SET); 

    size_t bytes_read;
    long current_pos;

    
    while ((bytes_read = fread(cipher_block, 1, AES_BLOCK_SIZE, fin)) == AES_BLOCK_SIZE) {
        
        
        current_pos = ftell(fin) - AES_BLOCK_SIZE;
        int is_last_block = (current_pos == file_size);
        
        
        aes_inv_cipher(cipher_block, decrypted_block, w);

       
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            final_plaintext_block[i] = decrypted_block[i] ^ prev_cipher_block[i];
        }

        
        size_t bytes_to_write = AES_BLOCK_SIZE;
        
        if (is_last_block) {
           
            bytes_to_write = pkcs7_unpad(final_plaintext_block, AES_BLOCK_SIZE);
        }

        fwrite(final_plaintext_block, 1, bytes_to_write, fout);

        
        memcpy(prev_cipher_block, cipher_block, AES_BLOCK_SIZE);
    }

    printf("✅ Descriptografia de '%s' para '%s' (CBC) concluída.\n", input_filename, output_filename);

    fclose(fin);
    fclose(fout);
    free(w);
}

int main() {
    
    
    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    
    const char *INPUT_FILE = "input.txt"; 
    
    const char *CIPHER_FILE = "output.aes"; 
    
    const char *DECRYPTED_FILE = "output_decrypted.txt"; 

    
    printf("--- Etapa de Criptografia ---\n");
    aes_encrypt_cbc(INPUT_FILE, CIPHER_FILE, key, sizeof(key));
    
    printf("\n");

    
    printf("--- Etapa de Descriptografia ---\n");
    aes_decrypt_cbc(CIPHER_FILE, DECRYPTED_FILE, key, sizeof(key));
    
    printf("\nProcesso Completo.\n");
    printf("Verifique o arquivo cifrado binário: '%s'\n", CIPHER_FILE);
    printf("Verifique se o decifrado ('%s') é idêntico ao original ('%s').\n", DECRYPTED_FILE, INPUT_FILE);

    return 0;
}