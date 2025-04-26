#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "10.0.2.15"
#define SERVER_PORT 5002
#define BUFFER_SIZE 65535

// Certificate file paths
#define CA_CERT "ca.crt"      // Certificate Authority certificate
#define CLIENT_CERT "client.crt"  // Client certificate
#define CLIENT_KEY "client.key"   // Client private key

// For data encryption/decryption
unsigned char AES_KEY_DATA[32] = "your-256-bit-key-123456789012345";
unsigned char AES_IV[16] = "1234567890abcdef";

// Initialize OpenSSL and create SSL context
SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    // Create new SSL context with TLS method
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load CA certificate for verification
    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set verification mode
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Load client certificate and key (if mutual authentication is required)
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Print SSL certificate information
void print_certificate_info(SSL *ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Server certificate:\n");
        
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        
        X509_free(cert);
    } else {
        printf("No server certificate received!\n");
    }
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

int main() {
    // Create SSL context
    SSL_CTX *ctx = create_ssl_context();
    
    // Create socket
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Socket creation failed");
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    
    // Set up server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(SERVER_PORT);
    
    // Connect to server
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(client_socket);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    
    printf("TCP connection established with %s:%d\n", SERVER_IP, SERVER_PORT);
    
    // Create new SSL connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);
    
    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_socket);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    
    printf("SSL connection established using %s\n", SSL_get_cipher(ssl));
    print_certificate_info(ssl);
    
    // Main communication loop
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
        
        // Encrypt the message
        int length = strlen((char *)buffer) + 1;
        int encrypted_length;
        encrypt_packet(buffer, encrypted_buffer, length, &encrypted_length);
        
        // Send the encrypted message using SSL
        SSL_write(ssl, &encrypted_length, sizeof(int));
        SSL_write(ssl, encrypted_buffer, encrypted_length);
        
        // Receive the response
        int encrypted_response_length;
        int received_bytes = SSL_read(ssl, &encrypted_response_length, sizeof(int));
        if (received_bytes <= 0) {
            int ssl_error = SSL_get_error(ssl, received_bytes);
            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                printf("Server closed connection\n");
            } else {
                ERR_print_errors_fp(stderr);
                printf("SSL read error (%d)\n", ssl_error);
            }
            break;
        }
        
        received_bytes = SSL_read(ssl, encrypted_buffer, encrypted_response_length);
        if (received_bytes <= 0) break;
        
        // Decrypt the response
        int decrypted_response_length;
        decrypt_packet(encrypted_buffer, decrypted_buffer, received_bytes, &decrypted_response_length);
        printf("Server Response: %s\n", decrypted_buffer);
    }
    
    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    
    return EXIT_SUCCESS;
}
