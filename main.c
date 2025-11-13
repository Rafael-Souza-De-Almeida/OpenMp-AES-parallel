#include <stdio.h>
#include "aes.h"
#include <stdlib.h>
#include <string.h>
#include <omp.h>

#define AES_BLOCK_SIZE 16
#define THREAD_NUM 8 

size_t pkcs7_pad_buffer(uint8_t *buffer, size_t data_len, size_t total_buffer_size) {
    uint8_t padding_len = AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE);
    if (data_len + padding_len > total_buffer_size) return 0; 
    for (size_t i = 0; i < padding_len; i++) {
        buffer[data_len + i] = padding_len;
    }
    return data_len + padding_len;
}

size_t pkcs7_unpad_buffer(uint8_t *buffer, size_t data_len) {
    if (data_len == 0) return 0;
    uint8_t padding_len = buffer[data_len - 1];
    if (padding_len == 0 || padding_len > AES_BLOCK_SIZE) return data_len; 
    return data_len - padding_len;
}

void aes_encrypt_ecb(const char *input_filename, const char *output_filename, uint8_t *key, size_t key_size) {
    FILE *fin = fopen(input_filename, "rb");
    FILE *fout = fopen(output_filename, "wb");
    if (!fin || !fout) { perror("Erro IO"); return; }

    uint8_t *w = aes_init(key_size);
    aes_key_expansion(key, w);

    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    rewind(fin);

    size_t num_blocks = (file_size / AES_BLOCK_SIZE) + 1;
    size_t padded_size = num_blocks * AES_BLOCK_SIZE;

    uint8_t *input_data = calloc(padded_size, 1); 
    uint8_t *output_data = malloc(padded_size);

    fread(input_data, 1, file_size, fin);
    
    pkcs7_pad_buffer(input_data, file_size, padded_size);

    double start = omp_get_wtime();

    #pragma omp parallel for
    for (size_t i = 0; i < num_blocks; i++) {
        
        uint8_t *p_in = input_data + (i * AES_BLOCK_SIZE);
        uint8_t *p_out = output_data + (i * AES_BLOCK_SIZE);

        aes_cipher(p_in, p_out, w);
    }

    double end = omp_get_wtime();
    printf("Tempo Criptografia ECB: %f s\n", end - start);

    
    fwrite(output_data, 1, padded_size, fout);

    free(input_data);
    free(output_data);
    free(w);
    fclose(fin);
    fclose(fout);
}


void aes_decrypt_ecb(const char *input_filename, const char *output_filename, uint8_t *key, size_t key_size) {
    FILE *fin = fopen(input_filename, "rb");
    FILE *fout = fopen(output_filename, "wb");
    if (!fin || !fout) { perror("Erro IO"); return; }

    uint8_t *w = aes_init(key_size);
    aes_key_expansion(key, w);

    
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    rewind(fin);

    if (file_size % AES_BLOCK_SIZE != 0) {
        printf("Erro: Arquivo corrompido (tamanho não múltiplo de 16)\n");
        return;
    }

    size_t num_blocks = file_size / AES_BLOCK_SIZE;
    
    uint8_t *input_data = malloc(file_size);
    uint8_t *output_data = malloc(file_size);

    fread(input_data, 1, file_size, fin);

    double start = omp_get_wtime();

    
    #pragma omp parallel for
    for (size_t i = 0; i < num_blocks; i++) {
        uint8_t *p_in = input_data + (i * AES_BLOCK_SIZE);
        uint8_t *p_out = output_data + (i * AES_BLOCK_SIZE);

        aes_inv_cipher(p_in, p_out, w);
    }

    double end = omp_get_wtime();
    printf("Tempo Descriptografia ECB: %f s\n", end - start);

    size_t final_size = pkcs7_unpad_buffer(output_data, file_size);

    fwrite(output_data, 1, final_size, fout);

    free(input_data);
    free(output_data);
    free(w);
    fclose(fin);
    fclose(fout);
}

int main() {
    omp_set_num_threads(THREAD_NUM);

    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    const char *INPUT_FILE = "input.txt"; 
    const char *ENC_FILE = "output.aes";
    const char *DEC_FILE = "output_decrypted.txt";

    printf("--- AES ECB (Modo Paralelo) ---\n");
    aes_encrypt_ecb(INPUT_FILE, ENC_FILE, key, sizeof(key));
    aes_decrypt_ecb(ENC_FILE, DEC_FILE, key, sizeof(key));

    printf("Concluido.\n");
    return 0;
}
