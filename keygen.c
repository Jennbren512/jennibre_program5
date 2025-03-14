#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ALPHABET_SIZE 27

// Function to generate random key
char generate_random_char() {
    int random_index = rand() % ALPHABET_SIZE;
    if (random_index == 26) return ' '; // Space character
    return 'A' + random_index;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <key_length>\n", argv[0]);
        exit(1);
    }

    int key_length = atoi(argv[1]);
    if (key_length <= 0) {
        fprintf(stderr, "Key length must be a positive integer\n");
        exit(1);
    }

    // Initialize random number generator
    srand(time(NULL));

    // Generate and print the random key
    for (int i = 0; i < key_length; i++) {
        printf("%c", generate_random_char());
    }
    printf("\n");

    return 0;
}
