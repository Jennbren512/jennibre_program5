#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 12345

// Function to read input with validation
void read_input(char *buffer, int size) {
    fgets(buffer, size, stdin);
    buffer[strcspn(buffer, "\n")] = '\0'; // Remove trailing newline
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char plaintext[1024], key[1024], ciphertext[1024];

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the encryption server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        close(sockfd);
        exit(1);
    }

    // Get plaintext and key from the user
    printf("Enter plaintext: ");
    read_input(plaintext, sizeof(plaintext));

    printf("Enter key: ");
    read_input(key, sizeof(key));

    // Send plaintext and key to the server
    write(sockfd, plaintext, strlen(plaintext));
    write(sockfd, key, strlen(key));

    // Receive the ciphertext
    read(sockfd, ciphertext, sizeof(ciphertext));
    printf("Ciphertext: %s\n", ciphertext);

    close(sockfd);
    return 0;
}
