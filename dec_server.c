#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_BUFFER 100000

void error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

// Read file into buffer, remove trailing newline
int read_file(const char *filename, char *buffer) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;
    fgets(buffer, MAX_BUFFER, fp);
    fclose(fp);
    size_t len = strlen(buffer);
    if (buffer[len - 1] == '\n') buffer[len - 1] = '\0';
    return 0;
}

// Validate text only contains A-Z and space
int validate_text(const char *text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if ((text[i] < 'A' || text[i] > 'Z') && text[i] != ' ') {
            return 0;
        }
    }
    return 1;
}

// Write exactly n bytes
int write_all(int socketFD, char *buffer, int n) {
    int total = 0, bytesWritten;
    while (total < n) {
        bytesWritten = send(socketFD, buffer + total, n - total, 0);
        if (bytesWritten <= 0) return -1;
        total += bytesWritten;
    }
    return total;
}

// Read exactly n bytes
int read_all(int socketFD, char *buffer, int n) {
    int total = 0, bytesRead;
    while (total < n) {
        bytesRead = recv(socketFD, buffer + total, n - total, 0);
        if (bytesRead <= 0) return -1;
        total += bytesRead;
    }
    return total;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "USAGE: %s ciphertext key port\n", argv[0]);
        exit(1);
    }

    char ciphertext[MAX_BUFFER];
    char key[MAX_BUFFER];
    char plaintext[MAX_BUFFER];
    memset(ciphertext, '\0', sizeof(ciphertext));
    memset(key, '\0', sizeof(key));
    memset(plaintext, '\0', sizeof(plaintext));

    if (read_file(argv[1], ciphertext) < 0 || read_file(argv[2], key) < 0) {
        fprintf(stderr, "Error reading files\n");
        exit(1);
    }

    if (!validate_text(ciphertext) || !validate_text(key)) {
        fprintf(stderr, "dec_client error: input contains bad characters\n");
        exit(1);
    }

    if (strlen(key) < strlen(ciphertext)) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        exit(1);
    }

    int port = atoi(argv[3]);
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) error("Error opening socket");

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        fprintf(stderr, "Error: could not contact dec_server on port %d\n", port);
        exit(2);
    }

    // Handshake
    char buffer[16];
    memset(buffer, 0, sizeof(buffer));
    send(socketFD, "DEC_CLIENT", 10, 0);
    recv(socketFD, buffer, sizeof(buffer) - 1, 0);
    if (strcmp(buffer, "DEC_SERVER") != 0) {
        fprintf(stderr, "Error: could not contact dec_server on port %d\n", port);
        close(socketFD);
        exit(2);
    }

    int textSize = strlen(ciphertext);
    send(socketFD, &textSize, sizeof(int), 0);
    write_all(socketFD, ciphertext, textSize);
    write_all(socketFD, key, textSize);

    if (read_all(socketFD, plaintext, textSize) < 0) {
        fprintf(stderr, "Error receiving data: Connection reset by peer\n");
        exit(1);
    }

    plaintext[textSize] = '\0';
    printf("%s\n", plaintext);
    close(socketFD);
    return 0;
}