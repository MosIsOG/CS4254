#ifndef RESPONSE_H
#define RESPONSE_H

#include <stddef.h>

typedef enum {
    RESP_ANSWERS,
    RESP_NOTFOUND,
    RESP_ERROR
} DnsResult;

int isResponseToQuery(const unsigned char *pkt, size_t len);
DnsResult parseDnsResponse(const unsigned char *resp, size_t resp_len,
                           const unsigned char *query, size_t query_len,
                           char *err, size_t err_len);

#endif
