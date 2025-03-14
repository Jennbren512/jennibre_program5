#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 54321

// Function to read input with validation
void read_input(char *buffer, int size) {
    fgets(buffer, size, stdin);
    buffer[strcspn(buffer, "\n")] = '\0'; // Remove trailing newline
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char ciphertext[1024], key[1024], plaintext[1024];

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the decryption server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        close(sockfd);
        exit(1);
    }

    // Get ciphertext and key from the user
    printf("Enter ciphertext: ");
    read_input(ciphertext, sizeof(ciphertext));

    printf("Enter key: ");
    read_input(key, sizeof(key));

    // Send ciphertext and key to the server
    write(sockfd, ciphertext, strlen(ciphertext));
    write(sockfd, key, strlen(key));

    // Receive the plaintext
    read(sockfd, plaintext, sizeof(plaintext));
    printf("Plaintext: %s\n", plaintext);

    close(sockfd);
    return 0;
}
