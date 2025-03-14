#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>

#define MAX_CLIENTS 5
#define PORT 12345

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

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char plaintext[1024], key[1024], ciphertext[1024];

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

    printf("Encryption server is running on port %d...\n", PORT);

    // Accept client connections and handle encryption
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd == -1) {
            perror("Accept failed");
            continue;
        }

        // Read plaintext and key from client
        read(client_fd, plaintext, sizeof(plaintext));
        read(client_fd, key, sizeof(key));

        // Encrypt data
        encrypt(plaintext, key, ciphertext);

        // Send encrypted ciphertext back to client
        write(client_fd, ciphertext, strlen(ciphertext));

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
