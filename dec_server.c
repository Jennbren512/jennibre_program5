#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define BUFFER_SIZE 100000

void error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

// Decrypt function using OTP
void decrypt(const char *ciphertext, const char *key, char *plaintext) {
    int i;
    for (i = 0; ciphertext[i] != '\0'; i++) {
        int c = (ciphertext[i] == ' ') ? 26 : ciphertext[i] - 'A';
        int k = (key[i] == ' ') ? 26 : key[i] - 'A';
        int p = (c - k + 27) % 27;
        plaintext[i] = (p == 26) ? ' ' : 'A' + p;
    }
    plaintext[i] = '\0';
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

void handle_connection(int connectionFD) {
    char handshake[16];
    memset(handshake, 0, sizeof(handshake));
    recv(connectionFD, handshake, sizeof(handshake) - 1, 0);

    if (strcmp(handshake, "DEC_CLIENT") != 0) {
        send(connectionFD, "REJECT", 6, 0);
        close(connectionFD);
        exit(1);
    } else {
        send(connectionFD, "DEC_SERVER", 10, 0);
    }

    // Get sizes first
    int textSize;
    recv(connectionFD, &textSize, sizeof(int), 0);

    char *ciphertext = malloc(textSize + 1);
    char *key = malloc(textSize + 1);
    char *plaintext = malloc(textSize + 1);
    memset(ciphertext, 0, textSize + 1);
    memset(key, 0, textSize + 1);
    memset(plaintext, 0, textSize + 1);

    if (read_all(connectionFD, ciphertext, textSize) < 0 ||
        read_all(connectionFD, key, textSize) < 0) {
        fprintf(stderr, "Error reading ciphertext/key\n");
        close(connectionFD);
        exit(1);
    }

    decrypt(ciphertext, key, plaintext);

    write_all(connectionFD, plaintext, textSize);

    free(ciphertext);
    free(key);
    free(plaintext);
    close(connectionFD);
    exit(0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    }

    int listenSocketFD, connectionFD;
    socklen_t sizeOfClientInfo;
    struct sockaddr_in serverAddress, clientAddress;

    listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocketFD < 0) error("ERROR opening socket");

    int yes = 1;
    setsockopt(listenSocketFD, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    memset((char *)&serverAddress, '\0', sizeof(serverAddress));
    int portNumber = atoi(argv[1]);
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(portNumber);
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        error("ERROR on binding");

    listen(listenSocketFD, 5);

    while (1) {
        sizeOfClientInfo = sizeof(clientAddress);
        connectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
        if (connectionFD < 0) {
            fprintf(stderr, "ERROR on accept\n");
            continue;
        }

        pid_t pid = fork();
        if (pid == 0) {
            // In child process
            close(listenSocketFD);
            handle_connection(connectionFD);
        } else {
            // Parent
            close(connectionFD);
        }
    }

    close(listenSocketFD);
    return 0;
}