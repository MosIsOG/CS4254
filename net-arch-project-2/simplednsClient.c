#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "dns.h"
#include "response.h"

#define MAX_BUFFER 512
#define MAX_RESPONSE 65536
#define TIMEOUT_MS 5000

void dump_packet(unsigned char *buf, int size) {
    for (int i = 0; i < size; i++) {
        if (i % 16 == 0 && i != 0) printf("\n");
        if (i % 16 == 0) printf("[%04x] ", i);
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

// Parse "@a.b.c.d" or "@a.b.c.d:port" (port defaults to 53).
static int parseServer(const char *arg, struct sockaddr_in *addr) {
    char host[INET_ADDRSTRLEN];
    const char *colon;
    size_t host_len;
    long port = 53;

    if (arg[0] != '@')
        return -1;
    arg++;

    colon = strchr(arg, ':');
    host_len = colon ? (size_t)(colon - arg) : strlen(arg);
    if (host_len == 0 || host_len >= sizeof host)
        return -1;
    memcpy(host, arg, host_len);
    host[host_len] = '\0';

    if (colon) {
        char *end;
        const char *digits = colon + 1;
        if (*digits < '0' || *digits > '9')
            return -1;
        errno = 0;
        port = strtol(digits, &end, 10);
        if (errno != 0 || *end != '\0' || port < 1 || port > 65535)
            return -1;
    }

    memset(addr, 0, sizeof *addr);
    addr->sin_family = AF_INET;
    addr->sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr->sin_addr) != 1)
        return -1;
    return 0;
}

static long elapsedMs(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000L + (now.tv_nsec - start->tv_nsec) / 1000000L;
}

// Wait up to 5 seconds total for our reply. Packets from other addresses or
// with the wrong ID are ignored without restarting the timer.
static int waitForResponse(int sockfd, const struct sockaddr_in *server,
                           const unsigned char *query, int query_size) {
    static unsigned char resp[MAX_RESPONSE];
    struct timespec start;
    char err[256];

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (;;) {
        long remaining = TIMEOUT_MS - elapsedMs(&start);
        if (remaining <= 0) {
            printf("NORESPONSE\n");
            return 0;
        }

        struct pollfd pfd = { .fd = sockfd, .events = POLLIN };
        int ready = poll(&pfd, 1, (int)remaining);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            printf("ERROR\tWaiting for a response failed: %s\n", strerror(errno));
            return 1;
        }
        if (ready == 0)
            continue;

        struct sockaddr_in from;
        socklen_t from_len = sizeof from;
        ssize_t n = recvfrom(sockfd, resp, sizeof resp, 0, (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            printf("ERROR\tReceive failed: %s\n", strerror(errno));
            return 1;
        }

        if (from_len < sizeof from || from.sin_family != AF_INET ||
            from.sin_addr.s_addr != server->sin_addr.s_addr ||
            from.sin_port != server->sin_port)
            continue;
        if (!isResponseToQuery(resp, (size_t)n))
            continue;

        switch (parseDnsResponse(resp, (size_t)n, query, (size_t)query_size, err, sizeof err)) {
        case RESP_ANSWERS:
            break;
        case RESP_NOTFOUND:
            printf("NOTFOUND\n");
            break;
        case RESP_ERROR:
            printf("ERROR\t%s\n", err);
            break;
        }
        return 0;
    }
}

int main(int argc, char *argv[]) {
    struct sockaddr_in server_addr;
    unsigned char buf[MAX_BUFFER];

    if (argc != 3) {
        printf("Usage: ./simplednsClient @<server:port> <name>\n");
        return 1;
    }

    if (parseServer(argv[1], &server_addr) < 0) {
        printf("ERROR\tInvalid server '%s': expected @a.b.c.d or @a.b.c.d:port\n", argv[1]);
        return 1;
    }

    int query_size = createDnsRequest(buf, sizeof buf, argv[2]);
    if (query_size < 0) {
        printf("ERROR\tInvalid name '%s': labels must be 1-63 bytes and the name at most 255 bytes\n",
               argv[2]);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("ERROR\tSocket creation failed: %s\n", strerror(errno));
        return 1;
    }

    dump_packet(buf, query_size);
    if (sendto(sockfd, buf, (size_t)query_size, 0, (struct sockaddr *)&server_addr,
               sizeof server_addr) != query_size) {
        printf("ERROR\tSend failed: %s\n", strerror(errno));
        close(sockfd);
        return 1;
    }

    int status = waitForResponse(sockfd, &server_addr, buf, query_size);
    close(sockfd);
    return status;
}
