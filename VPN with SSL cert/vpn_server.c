#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "10.0.2.15"
#define SERVER_PORT 5002
#define BUFFER_SIZE 65535

// Certificate and key file paths
#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"

// For data encryption/decryption
unsigned char AES_KEY_DATA[32] = "your-256-bit-key-123456789012345";
unsigned char AES_IV[16] = "1234567890abcdef";

// SSL context and error handling
SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    // Create new SSL context with TLS method
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

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

typedef struct {
    int socket;
    SSL *ssl;
} client_data;

// Client handler function
void *handle_client(void *arg) {
    client_data *data = (client_data *)arg;
    int client_socket = data->socket;
    SSL *ssl = data->ssl;
    free(data);
    
    printf("Client connected. Starting SSL handshake...\n");
    
    // SSL handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_socket);
        printf("SSL handshake failed\n");
        return NULL;
    }
    
    printf("SSL handshake successful. Cipher: %s\n", SSL_get_cipher(ssl));
    
    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted_buffer[BUFFER_SIZE];
    unsigned char encrypted_buffer[BUFFER_SIZE];
    
    while (1) {
        int encrypted_length;
        // Using SSL_read instead of recv
        int received_bytes = SSL_read(ssl, &encrypted_length, sizeof(int));
        if (received_bytes <= 0) {
            int error = SSL_get_error(ssl, received_bytes);
            if (error == SSL_ERROR_ZERO_RETURN) {
                printf("Connection closed by client\n");
            } else {
                printf("SSL read error (%d)\n", error);
            }
            break;
        }
        
        // Read the encrypted data
        received_bytes = SSL_read(ssl, buffer, encrypted_length);
        if (received_bytes <= 0) break;
        
        // Decrypt the data
        int decrypted_length;
        decrypt_packet(buffer, decrypted_buffer, received_bytes, &decrypted_length);
        printf("Decrypted Data: %s\n", decrypted_buffer);
        
        // Process and encrypt response
        int encrypted_response_length;
        encrypt_packet(decrypted_buffer, encrypted_buffer, decrypted_length, &encrypted_response_length);
        printf("Encrypted Response Length: %d\n", encrypted_response_length);
        printf("Encrypted Response: %s\n", encrypted_buffer);
        
        // Send response using SSL_write
        SSL_write(ssl, &encrypted_response_length, sizeof(int));
        SSL_write(ssl, encrypted_buffer, encrypted_response_length);
        printf("Sent Encrypted Response\n");
    }
    
    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
    printf("Client disconnected\n");
    return NULL;
}

int main() {
    // Create SSL context
    SSL_CTX *ctx = create_ssl_context();
    
    // Create server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Configure server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(SERVER_PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    
    // Listen for connections
    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        close(server_socket);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    
    printf("VPN Server with SSL started on %s:%d\n", SERVER_IP, SERVER_PORT);
    printf("Using certificates: %s and %s\n", CERT_FILE, KEY_FILE);
    
    // Main accept loop
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        // Get client IP for logging
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("New connection from: %s:%d\n", client_ip, ntohs(client_addr.sin_port));
        
        // Create new SSL structure for this connection
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);
        
        // Create client data structure
        client_data *data = malloc(sizeof(client_data));
        data->socket = client_socket;
        data->ssl = ssl;
        
        // Create thread to handle client
        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, handle_client, data) != 0) {
            perror("Failed to create thread");
            SSL_free(ssl);
            close(client_socket);
            free(data);
            continue;
        }
        
        pthread_detach(client_thread);
    }
    
    // Clean up (this code is unreachable in this example)
    close(server_socket);
    SSL_CTX_free(ctx);
    
    return EXIT_SUCCESS;
}
