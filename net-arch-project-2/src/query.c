#include <string.h>

#include "dns.h"
#include "query.h"

static void put16(unsigned char *p, uint16_t value) {
    p[0] = (unsigned char)(value >> 8);
    p[1] = (unsigned char)(value & 0xFF);
}

// Encode a dotted name as DNS labels (length byte + text, ending in 0).
// Returns the encoded length, or -1 if a label or the whole name is too long.
int createQNAME(const char *domain, unsigned char *qname_buf, size_t buf_len) {
    size_t domain_len = strlen(domain);
    size_t start = 0;
    size_t pos = 0;

    if (domain_len > 0 && domain[domain_len - 1] == '.')
        domain_len--;
    if (domain_len == 0)
        return -1;

    while (start <= domain_len) {
        size_t end = start;
        while (end < domain_len && domain[end] != '.')
            end++;

        size_t label_len = end - start;
        if (label_len == 0 || label_len > DNS_MAX_LABEL)
            return -1;
        if (pos + label_len + 2 > buf_len || pos + label_len + 2 > DNS_MAX_NAME)
            return -1;

        qname_buf[pos++] = (unsigned char)label_len;
        memcpy(qname_buf + pos, domain + start, label_len);
        pos += label_len;
        start = end + 1;
    }

    qname_buf[pos++] = 0;
    return (int)pos;
}

// Build the full query: header (ID 0x0539, recursion desired, 1 question)
// followed by the question for an A record. Returns the packet size or -1.
int createDnsRequest(unsigned char *req_buf, size_t buf_len, const char *domain) {
    if (buf_len < DNS_HEADER_SIZE)
        return -1;

    put16(req_buf, DNS_QUERY_ID);
    put16(req_buf + 2, DNS_FLAG_RD);
    put16(req_buf + 4, 1);
    put16(req_buf + 6, 0);
    put16(req_buf + 8, 0);
    put16(req_buf + 10, 0);

    int qname_len = createQNAME(domain, req_buf + DNS_HEADER_SIZE, buf_len - DNS_HEADER_SIZE);
    if (qname_len < 0)
        return -1;

    size_t pos = DNS_HEADER_SIZE + (size_t)qname_len;
    if (pos + 4 > buf_len)
        return -1;

    put16(req_buf + pos, QTYPE_A);
    put16(req_buf + pos + 2, DNS_CLASS_IN);
    return (int)(pos + 4);
}
