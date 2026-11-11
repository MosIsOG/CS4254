#ifndef QUERY_H
#define QUERY_H

#include <stddef.h>

typedef enum {
    QTYPE_A = 1,
    QTYPE_CNAME = 5
} DnsQueryType;

int createQNAME(const char *domain, unsigned char *qname_buf, size_t buf_len);

#endif
