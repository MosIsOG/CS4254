#ifndef DNS_H
#define DNS_H

#include <stddef.h>
#include <stdint.h>

#define DNS_QUERY_ID 0x0539
#define DNS_HEADER_SIZE 12
#define DNS_MAX_NAME 255
#define DNS_MAX_LABEL 63
#define DNS_CLASS_IN 1

#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_AA 0x0400
#define DNS_FLAG_TC 0x0200
#define DNS_FLAG_RD 0x0100
#define DNS_OPCODE(flags) (((flags) >> 11) & 0x0F)
#define DNS_RCODE(flags) ((flags) & 0x0F)

typedef enum {
    OP_STD_QUERY,
    OP_INV_QUERY,
    OP_STATUS_REQ
} DnsOpcode;

typedef enum {
    RCODE_NOERROR = 0,
    RCODE_FORMERR = 1,
    RCODE_SERVFAIL = 2,
    RCODE_NXDOMAIN = 3,
    RCODE_NOTIMP = 4,
    RCODE_REFUSED = 5
} DnsRcode;

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t num_quest;
    uint16_t num_ans_rr;
    uint16_t num_auth_rr;
    uint16_t num_add_rr;
} DnsHeader;

int createDnsRequest(unsigned char *req_buf, size_t buf_len, const char *domain);
void readDnsHeader(const unsigned char *pkt, DnsHeader *hdr);

#endif
