#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 100000
#define CHUNK_SIZE 1000

void encrypt(const char *plaintext, const char *key, char *ciphertext) {
    int i;
    for (i = 0; plaintext[i] != '\0'; i++) {
        int p = (plaintext[i] == ' ') ? 26 : plaintext[i] - 'A';
        int k = (key[i] == ' ') ? 26 : key[i] - 'A';
        int c = (p + k) % 27;
        ciphertext[i] = (c == 26) ? ' ' : 'A' + c;
    }
    ciphertext[i] = '\0';
}

int read_all(int fd, char *buffer, int n) {
    int total = 0, bytesRead;
    while (total < n) {
        bytesRead = recv(fd, buffer + total, n - total, 0);
        if (bytesRead <= 0) return -1;
        total += bytesRead;
    }
    return total;
}

int write_all(int fd, char *buffer, int n) {
    int total = 0, bytesWritten;
    while (total < n) {
        int chunk = (n - total > CHUNK_SIZE) ? CHUNK_SIZE : (n - total);
        bytesWritten = send(fd, buffer + total, chunk, 0);
        if (bytesWritten <= 0) return -1;
        total += bytesWritten;
    }
    return total;
}

void handle_connection(int connectionFD) {
    char handshake[16];
    memset(handshake, 0, sizeof(handshake));
    recv(connectionFD, handshake, sizeof(handshake) - 1, 0);

    if (strcmp(handshake, "ENC_CLIENT") != 0) {
        send(connectionFD, "REJECT", 6, 0);
        close(connectionFD);
        exit(1);
    }
    send(connectionFD, "ENC_SERVER", 10, 0);

    int textSize;
    recv(connectionFD, &textSize, sizeof(int), 0);

    char *plaintext = malloc(textSize + 1);
    char *key = malloc(textSize + 1);
    char *ciphertext = malloc(textSize + 1);
    memset(plaintext, 0, textSize + 1);
    memset(key, 0, textSize + 1);
    memset(ciphertext, 0, textSize + 1);

    if (read_all(connectionFD, plaintext, textSize) < 0 ||
        read_all(connectionFD, key, textSize) < 0) {
        close(connectionFD);
        exit(1);
    }

    encrypt(plaintext, key, ciphertext);
    write_all(connectionFD, ciphertext, textSize);

    free(plaintext);
    free(key);
    free(ciphertext);
    close(connectionFD);
    exit(0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    }

    int listenFD, connFD;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t clientLen = sizeof(clientAddr);
    int port = atoi(argv[1]);

    listenFD = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(listenFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind");
        exit(1);
    }

    listen(listenFD, 5);

    while (1) {
        connFD = accept(listenFD, (struct sockaddr *)&clientAddr, &clientLen);
        if (connFD < 0) continue;

        pid_t pid = fork();
        if (pid == 0) {
            close(listenFD);
            handle_connection(connFD);
        } else {
            close(connFD);
        }
    }

    close(listenFD);
    return 0;
}
