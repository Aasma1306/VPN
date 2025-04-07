#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
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

// Client handler function
void *handle_client(void *arg) {
    int client_socket = *(int *)arg;
    free(arg);
    
    printf("Client connected.\n");

    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted_buffer[BUFFER_SIZE];
    unsigned char encrypted_buffer[BUFFER_SIZE];

    while (1) {
        int encrypted_length;
        ssize_t received_bytes = recv(client_socket, &encrypted_length, sizeof(int), 0);
        if (received_bytes <= 0) break;

        received_bytes = recv(client_socket, buffer, encrypted_length, 0);
        if (received_bytes <= 0) break;

        int decrypted_length;
        decrypt_packet(buffer, decrypted_buffer, received_bytes, &decrypted_length);
        printf("Decrypted Data: %s\n", decrypted_buffer);

        int encrypted_response_length;
        encrypt_packet(decrypted_buffer, encrypted_buffer, decrypted_length, &encrypted_response_length);

        send(client_socket, &encrypted_response_length, sizeof(int), 0);
        send(client_socket, encrypted_buffer, encrypted_response_length, 0);

        printf("Sent Encrypted Response\n");
    }

    close(client_socket);
    printf("Client disconnected\n");
    return NULL;
}

int main() {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        return EXIT_FAILURE;
    }

    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        close(server_socket);
        return EXIT_FAILURE;
    }

    printf("VPN Server started on %s:%d\n", SERVER_IP, SERVER_PORT);

    while (1) {
        int *client_socket = malloc(sizeof(int));
        *client_socket = accept(server_socket, NULL, NULL);
        if (*client_socket < 0) {
            perror("Accept failed");
            free(client_socket);
            continue;
        }

        pthread_t client_thread;
        pthread_create(&client_thread, NULL, handle_client, client_socket);
        pthread_detach(client_thread);
    }

    close(server_socket);
    return EXIT_SUCCESS;
}
