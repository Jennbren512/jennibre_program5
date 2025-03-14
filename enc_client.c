#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 100000
#define CHUNK_SIZE 1000

void error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

int read_file(const char *filename, char *buffer) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;
    fgets(buffer, BUFFER_SIZE, fp);
    fclose(fp);
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') buffer[len - 1] = '\0';
    return 0;
}

int validate(const char *text) {
    for (int i = 0; text[i]; i++) {
        if ((text[i] < 'A' || text[i] > 'Z') && text[i] != ' ') return 0;
    }
    return 1;
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

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "USAGE: %s plaintext key port\n", argv[0]);
        exit(1);
    }

    char plaintext[BUFFER_SIZE], key[BUFFER_SIZE], ciphertext[BUFFER_SIZE];
    memset(plaintext, 0, sizeof(plaintext));
    memset(key, 0, sizeof(key));
    memset(ciphertext, 0, sizeof(ciphertext));

    if (read_file(argv[1], plaintext) < 0 || read_file(argv[2], key) < 0) {
        fprintf(stderr, "Error reading input files\n");
        exit(1);
    }

    if (!validate(plaintext) || !validate(key)) {
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        exit(1);
    }

    if (strlen(key) < strlen(plaintext)) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        exit(1);
    }

    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(atoi(argv[3]));
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(socketFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %s\n", argv[3]);
        exit(2);
    }

    // Handshake
    char buffer[16] = {0};
    send(socketFD, "ENC_CLIENT", 10, 0);
    recv(socketFD, buffer, sizeof(buffer) - 1, 0);
    if (strcmp(buffer, "ENC_SERVER") != 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %s\n", argv[3]);
        close(socketFD);
        exit(2);
    }

    int textSize = strlen(plaintext);
    send(socketFD, &textSize, sizeof(int), 0);
    write_all(socketFD, plaintext, textSize);
    write_all(socketFD, key, textSize);

    if (read_all(socketFD, ciphertext, textSize) < 0) {
        fprintf(stderr, "Error receiving data from server\n");
        exit(1);
    }

    ciphertext[textSize] = '\0';
    printf("%s\n", ciphertext);

    close(socketFD);
    return 0;
}
