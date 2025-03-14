#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_CLIENTS 5
#define PORT 54321

// Decrypt function using OTP (One-Time Pad)
void decrypt(char *ciphertext, char *key, char *plaintext) {
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        int c = (ciphertext[i] == ' ') ? 26 : ciphertext[i] - 'A';
        int k = (key[i] == ' ') ? 26 : key[i] - 'A';
        plaintext[i] = (c - k + 27) % 27 + 'A';
        if (plaintext[i] == 27 + 'A') plaintext[i] = ' ';
    }
    plaintext[strlen(ciphertext)] = '\0';
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char ciphertext[1024], key[1024], plaintext[1024];

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

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

    printf("Decryption server is running on port %d...\n", PORT);

    // Accept client connections and handle decryption
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);

        char client_id[BUFFER_SIZE] = {0};
        recv(client_fd, client_id, sizeof(client_id) - 1, 0);

        if (strcmp(client_id, "dec_client") != 0) {
            char *msg = "ERROR: Unauthorized client";
            send(client_fd, msg, strlen(msg), 0);
            close(client_fd);
            continue;
        }
    
        if (client_fd == -1) {
            perror("Accept failed");
            continue;
        }

        // Read ciphertext and key from client
        read(client_fd, ciphertext, sizeof(ciphertext));
        read(client_fd, key, sizeof(key));

        // Decrypt data
        decrypt(ciphertext, key, plaintext);

        // Send decrypted plaintext back to client
        write(client_fd, plaintext, strlen(plaintext));

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
