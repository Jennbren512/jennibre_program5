#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024

// Encrypt function using OTP (One-Time Pad)
void encrypt(char *plaintext, char *key, char *ciphertext) {
    for (int i = 0; plaintext[i] != '\0'; i++) {
        int p = (plaintext[i] == ' ') ? 26 : plaintext[i] - 'A';
        int k = (key[i] == ' ') ? 26 : key[i] - 'A';
        ciphertext[i] = (p + k) % 27 + 'A';
        if (ciphertext[i] == 27 + 'A') ciphertext[i] = ' ';
    }
    ciphertext[strlen(plaintext)] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(1);
    }
    int port = atoi(argv[1]);

    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char plaintext[BUFFER_SIZE] = {0}, key[BUFFER_SIZE] = {0}, ciphertext[BUFFER_SIZE] = {0};

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Binding failed");
        close(server_fd);
        exit(1);
    }

    // Listen for incoming connections
    if (listen(server_fd, MAX_CLIENTS) == -1) {
        perror("Listen failed");
        close(server_fd);
        exit(1);
    }

    printf("Encryption server is running on port %d...\n", port);

    // Accept client connections and handle encryption
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd == -1) {
            perror("Accept failed");
            continue;
        }

        // Read plaintext
        ssize_t bytes_read = recv(client_fd, plaintext, BUFFER_SIZE - 1, 0);
        if (bytes_read <= 0) {
            perror("Error reading plaintext");
            close(client_fd);
            continue;
        }
        plaintext[bytes_read] = '\0';  // Ensure null termination

        // Read key
        bytes_read = recv(client_fd, key, BUFFER_SIZE - 1, 0);
        if (bytes_read <= 0) {
            perror("Error reading key");
            close(client_fd);
            continue;
        }
        key[bytes_read] = '\0';

        // Encrypt data
        encrypt(plaintext, key, ciphertext);

        // Send ciphertext back to client
        send(client_fd, ciphertext, strlen(ciphertext), 0);

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
