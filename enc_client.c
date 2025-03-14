#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <plaintext_file> <key_file> <port>\n", argv[0]);
        exit(1);
    }

    // Read command-line arguments
    char *plaintext_file = argv[1];
    char *key_file = argv[2];
    int port = atoi(argv[3]);

    // Read plaintext from file
    FILE *fp = fopen(plaintext_file, "r");
    if (!fp) {
        perror("Error opening plaintext file");
        exit(1);
    }
    char plaintext[BUFFER_SIZE] = {0};
    fgets(plaintext, BUFFER_SIZE - 1, fp);
    fclose(fp);
    size_t plaintext_len = strlen(plaintext);
    if (plaintext[plaintext_len - 1] == '\n') plaintext[--plaintext_len] = '\0'; // Remove newline

    // Read key from file
    fp = fopen(key_file, "r");
    if (!fp) {
        perror("Error opening key file");
        exit(1);
    }
    char key[BUFFER_SIZE] = {0};
    fgets(key, BUFFER_SIZE - 1, fp);
    fclose(fp);
    size_t key_len = strlen(key);
    if (key[key_len - 1] == '\n') key[--key_len] = '\0'; // Remove newline

    // Check if key is long enough
    if (key_len < plaintext_len) {
        fprintf(stderr, "Error: Key is too short\n");
        exit(1);
    }

    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    // Set up server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        close(sockfd);
        exit(1);
    }

    // Send plaintext and key to server
    send(sockfd, plaintext, plaintext_len, 0);
    send(sockfd, key, key_len, 0);

    // Receive encrypted text from server
    char ciphertext[BUFFER_SIZE] = {0};
    size_t received = 0;
    while (received < plaintext_len) {
        ssize_t bytes = recv(sockfd, ciphertext + received, plaintext_len - received, 0);
        if (bytes <= 0) {
            perror("Error receiving data");
            close(sockfd);
            exit(1);
        }
        received += bytes;
    }

    // Ensure proper null-termination
    ciphertext[plaintext_len] = '\0';

    // Print only the expected number of characters
    printf("%s\n", ciphertext);

    // Clean up
    close(sockfd);
    return 0;
}
