CC = gcc
CFLAGS = --std=gnu99 -Wall -Werror

all: enc_server enc_client dec_server dec_client keygen

enc_server: enc_server.c
	$(CC) $(CFLAGS) -o enc_server enc_server.c

enc_client: enc_client.c
	$(CC) $(CFLAGS) -o enc_client enc_client.c

dec_server: dec_server.c
	$(CC) $(CFLAGS) -o dec_server dec_server.c

dec_client: dec_client.c
	$(CC) $(CFLAGS) -o dec_client dec_client.c

keygen: keygen.c
	$(CC) $(CFLAGS) -o keygen keygen.c

clean:
	rm -f enc_server enc_client dec_server dec_client keygen
