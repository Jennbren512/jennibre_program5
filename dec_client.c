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
        fprintf(stderr, "Usage: %s <ciphertext_file> <key_file> <port>\n", argv[0]);
        exit(1);
    }

    // Read command-line arguments
    char *ciphertext_file = argv[1];
    char *key_file = argv[2];
    int port = atoi(argv[3]);

    // Read ciphertext from file
    FILE *fp = fopen(ciphertext_file, "r");
    if (!fp) {
        perror("Error opening ciphertext file");
        exit(1);
    }
    char ciphertext[BUFFER_SIZE] = {0};
    fgets(ciphertext, BUFFER_SIZE - 1, fp);
    fclose(fp);
    size_t ciphertext_len = strlen(ciphertext);
    if (ciphertext[ciphertext_len - 1] == '\n') ciphertext[--ciphertext_len] = '\0'; // Remove newline

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
    if (key_len < ciphertext_len) {
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

    printf("Connecting to server on port %d...\n", port);
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        close(sockfd);
        exit(1);
    }

    // Send ciphertext and key to server
    printf("Sending ciphertext and key...\n");
    send(sockfd, ciphertext, ciphertext_len, 0);
    send(sockfd, key, key_len, 0);

    // Receive decrypted text from server
    char decrypted_text[BUFFER_SIZE] = {0};
    size_t received = 0;
    printf("Waiting for response from server...\n");
    while (received < ciphertext_len) {
        ssize_t bytes = recv(sockfd, decrypted_text + received, ciphertext_len - received, 0);
        if (bytes <= 0) {
            perror("Error receiving data");
            close(sockfd);
            exit(1);
        }
        received += bytes;
    }

    // Ensure proper null-termination
    decrypted_text[ciphertext_len] = '\0';

    // Print only the expected number of characters
    printf("Decrypted text: %s\n", decrypted_text);

    // Clean up
    close(sockfd);
    return 0;
}
