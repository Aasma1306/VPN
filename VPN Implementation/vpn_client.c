#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#define SERVER_IP "172.16.20.232"
#define SERVER_PORT 5000
#define BUFFER_SIZE 65535

unsigned char AES_KEY_DATA[32] = "your-256-bit-key-123456789012345";
unsigned char AES_IV[16] = "1234567890abcdef";

// Encrypt function with output length
void encrypt_packet(unsigned char *input, unsigned char *output, int length, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY_DATA, AES_IV);

    int len;
    EVP_EncryptUpdate(ctx, output, &len, input, length);
    *out_len = len;

    EVP_EncryptFinal_ex(ctx, output + len, &len);
    *out_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

// Decrypt function with output length
void decrypt_packet(unsigned char *input, unsigned char *output, int length, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY_DATA, AES_IV);

    int len;
    EVP_DecryptUpdate(ctx, output, &len, input, length);
    *out_len = len;

    EVP_DecryptFinal_ex(ctx, output + len, &len);
    *out_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(SERVER_PORT);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(client_socket);
        return EXIT_FAILURE;
    }

    printf("Connected to VPN server at %s:%d\n", SERVER_IP, SERVER_PORT);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted_buffer[BUFFER_SIZE];
    unsigned char decrypted_buffer[BUFFER_SIZE];

    while (1) {
        printf("Enter message: ");
        fgets((char *)buffer, BUFFER_SIZE, stdin);
        buffer[strcspn((char *)buffer, "\n")] = '\0';

        if (strcmp((char *)buffer, "exit") == 0) {
            break;
        }

        int length = strlen((char *)buffer) + 1;
        int encrypted_length;
        encrypt_packet(buffer, encrypted_buffer, length, &encrypted_length);

        send(client_socket, &encrypted_length, sizeof(int), 0);
        send(client_socket, encrypted_buffer, encrypted_length, 0);

        int encrypted_response_length;
        ssize_t received_bytes = recv(client_socket, &encrypted_response_length, sizeof(int), 0);
        if (received_bytes <= 0) break;

        received_bytes = recv(client_socket, encrypted_buffer, encrypted_response_length, 0);
        if (received_bytes <= 0) break;

        int decrypted_response_length;
        decrypt_packet(encrypted_buffer, decrypted_buffer, received_bytes, &decrypted_response_length);

        printf("Server Response: %s\n", decrypted_buffer);
    }

    close(client_socket);
    return EXIT_SUCCESS;
}
