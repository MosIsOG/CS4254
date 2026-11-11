CC = gcc
CFLAGS = -Wall -Wextra -g -Iincludes

SRCS = simplednsClient.c src/query.c src/response.c
HEADERS = includes/dns.h includes/query.h includes/response.h

all: simplednsClient

simplednsClient: $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o simplednsClient $(SRCS)

clean:
	rm -f simplednsClient *.o src/*.o

test: simplednsClient
	chmod +x test.sh
	./test.sh

.PHONY: all clean test
