#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

#include "dns.h"
#include "query.h"
#include "response.h"

#define NAME_TEXT_MAX 1024
#define MAX_POINTER_JUMPS 64

static uint16_t get16(const unsigned char *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void setError(char *err, size_t err_len, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(err, err_len, fmt, args);
    va_end(args);
}

void readDnsHeader(const unsigned char *pkt, DnsHeader *hdr) {
    hdr->id = get16(pkt);
    hdr->flags = get16(pkt + 2);
    hdr->num_quest = get16(pkt + 4);
    hdr->num_ans_rr = get16(pkt + 6);
    hdr->num_auth_rr = get16(pkt + 8);
    hdr->num_add_rr = get16(pkt + 10);
}

// A packet is a reply to us only if it has our ID and the QR bit set;
// anything else is ignored by the caller.
int isResponseToQuery(const unsigned char *pkt, size_t len) {
    if (len < 4)
        return 0;
    return get16(pkt) == DNS_QUERY_ID && (get16(pkt + 2) & DNS_FLAG_QR);
}

static int appendChar(char *out, size_t out_len, size_t *out_pos, unsigned char ch) {
    char tmp[5];
    int n;

    if (ch == '.' || ch == '\\')
        n = snprintf(tmp, sizeof tmp, "\\%c", ch);
    else if (ch < 0x21 || ch > 0x7E)
        n = snprintf(tmp, sizeof tmp, "\\%03u", ch);
    else
        n = snprintf(tmp, sizeof tmp, "%c", ch);

    if (*out_pos + (size_t)n >= out_len)
        return -1;
    memcpy(out + *out_pos, tmp, (size_t)n);
    *out_pos += (size_t)n;
    return 0;
}

// Decode the name at offset into dotted text, following compression pointers.
// Pointers must point backwards so a malicious packet cannot loop forever.
// *next is set to the byte just after the name in the original position.
static int readName(const unsigned char *pkt, size_t len, size_t offset,
                    char *out, size_t out_len, size_t *next) {
    size_t pos = offset;
    size_t out_pos = 0;
    size_t wire_len = 1;
    int jumps = 0;
    int jumped = 0;

    for (;;) {
        if (pos >= len)
            return -1;

        unsigned char label_len = pkt[pos];

        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= len)
                return -1;
            size_t target = ((size_t)(label_len & 0x3F) << 8) | pkt[pos + 1];
            if (target >= pos || ++jumps > MAX_POINTER_JUMPS)
                return -1;
            if (!jumped)
                *next = pos + 2;
            jumped = 1;
            pos = target;
            continue;
        }

        if (label_len & 0xC0)
            return -1;

        if (label_len == 0) {
            if (!jumped)
                *next = pos + 1;
            break;
        }

        if (pos + 1 + label_len > len)
            return -1;
        wire_len += label_len + 1;
        if (wire_len > DNS_MAX_NAME)
            return -1;

        if (out_pos > 0) {
            if (out_pos + 1 >= out_len)
                return -1;
            out[out_pos++] = '.';
        }

        for (size_t i = 0; i < label_len; i++) {
            if (appendChar(out, out_len, &out_pos, pkt[pos + 1 + i]) < 0)
                return -1;
        }
        pos += 1 + label_len;
    }

    if (out_pos == 0) {
        if (out_len < 2)
            return -1;
        out[out_pos++] = '.';
    }
    out[out_pos] = '\0';
    return 0;
}

static const char *rcodeDescription(unsigned rcode) {
    switch (rcode) {
    case RCODE_FORMERR:
        return "Server could not interpret the query (FORMERR)";
    case RCODE_SERVFAIL:
        return "Server failure (SERVFAIL)";
    case RCODE_NOTIMP:
        return "Server does not support this query (NOTIMP)";
    case RCODE_REFUSED:
        return "Server refused the query (REFUSED)";
    default:
        return NULL;
    }
}

// Go through every resource record after the question, checking bounds.
// A and CNAME answers are counted in *found, and printed when print is set.
static int walkRecords(const unsigned char *resp, size_t resp_len, size_t offset,
                       unsigned answer_count, unsigned total_count, int print,
                       const char *auth, int *found, char *err, size_t err_len) {
    char owner[NAME_TEXT_MAX];
    char alias[NAME_TEXT_MAX];

    *found = 0;
    for (unsigned i = 0; i < total_count; i++) {
        size_t next;
        if (readName(resp, resp_len, offset, owner, sizeof owner, &next) < 0) {
            setError(err, err_len, "Malformed name in resource record %u", i + 1);
            return -1;
        }
        if (next + 10 > resp_len) {
            setError(err, err_len, "Resource record %u is truncated", i + 1);
            return -1;
        }

        uint16_t type = get16(resp + next);
        uint16_t rr_class = get16(resp + next + 2);
        uint16_t rd_len = get16(resp + next + 8);
        size_t rdata = next + 10;

        if (rdata + rd_len > resp_len) {
            setError(err, err_len, "Resource record %u data runs past the end of the packet", i + 1);
            return -1;
        }

        if (i < answer_count && (type == QTYPE_A || type == QTYPE_CNAME)) {
            if (rr_class != DNS_CLASS_IN) {
                setError(err, err_len, "Answer %u has unexpected class %u", i + 1, rr_class);
                return -1;
            }

            if (type == QTYPE_A) {
                if (rd_len != 4) {
                    setError(err, err_len, "A record has invalid length %u", rd_len);
                    return -1;
                }
                if (print) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, resp + rdata, ip, sizeof ip);
                    printf("IP\t%s\t%s\n", ip, auth);
                }
            } else {
                size_t alias_end;
                if (readName(resp, resp_len, rdata, alias, sizeof alias, &alias_end) < 0) {
                    setError(err, err_len, "Malformed name in CNAME record");
                    return -1;
                }
                if (alias_end != rdata + rd_len) {
                    setError(err, err_len, "CNAME record length does not match its data");
                    return -1;
                }
                if (print)
                    printf("CNAME\t%s\t%s\n", alias, auth);
            }
            (*found)++;
        }

        offset = rdata + rd_len;
    }

    if (offset != resp_len) {
        setError(err, err_len, "Unexpected %zu bytes after the last record", resp_len - offset);
        return -1;
    }
    return 0;
}

// Validate the whole response (header, question, all records) before
// printing anything, so a malformed packet only produces an ERROR line.
DnsResult parseDnsResponse(const unsigned char *resp, size_t resp_len,
                           const unsigned char *query, size_t query_len,
                           char *err, size_t err_len) {
    DnsHeader hdr;
    char asked[NAME_TEXT_MAX];
    char echoed[NAME_TEXT_MAX];
    size_t next;

    if (resp_len < DNS_HEADER_SIZE) {
        setError(err, err_len, "Response is too short (%zu bytes)", resp_len);
        return RESP_ERROR;
    }
    readDnsHeader(resp, &hdr);

    if (DNS_OPCODE(hdr.flags) != OP_STD_QUERY) {
        setError(err, err_len, "Response has unexpected opcode %u", DNS_OPCODE(hdr.flags));
        return RESP_ERROR;
    }
    if (hdr.flags & DNS_FLAG_TC) {
        setError(err, err_len, "Response was truncated by the server");
        return RESP_ERROR;
    }

    unsigned rcode = DNS_RCODE(hdr.flags);
    if (rcode != RCODE_NOERROR && rcode != RCODE_NXDOMAIN) {
        const char *desc = rcodeDescription(rcode);
        if (desc)
            setError(err, err_len, "%s", desc);
        else
            setError(err, err_len, "Server returned RCODE %u", rcode);
        return RESP_ERROR;
    }

    if (hdr.num_quest != 1) {
        setError(err, err_len, "Response contains %u questions instead of 1", hdr.num_quest);
        return RESP_ERROR;
    }
    if (readName(query, query_len, DNS_HEADER_SIZE, asked, sizeof asked, &next) < 0 ||
        readName(resp, resp_len, DNS_HEADER_SIZE, echoed, sizeof echoed, &next) < 0) {
        setError(err, err_len, "Malformed name in question section");
        return RESP_ERROR;
    }
    if (next + 4 > resp_len) {
        setError(err, err_len, "Question section is truncated");
        return RESP_ERROR;
    }
    if (strcasecmp(asked, echoed) != 0) {
        setError(err, err_len, "Response question '%s' does not match the query", echoed);
        return RESP_ERROR;
    }
    if (get16(resp + next) != QTYPE_A || get16(resp + next + 2) != DNS_CLASS_IN) {
        setError(err, err_len, "Response question type or class does not match the query");
        return RESP_ERROR;
    }

    size_t records = next + 4;
    unsigned total = (unsigned)hdr.num_ans_rr + hdr.num_auth_rr + hdr.num_add_rr;
    const char *auth = (hdr.flags & DNS_FLAG_AA) ? "auth" : "nonauth";
    int found;

    // First pass only checks the records; the second pass prints them.
    if (walkRecords(resp, resp_len, records, hdr.num_ans_rr, total, 0, auth, &found,
                    err, err_len) < 0)
        return RESP_ERROR;

    if (rcode == RCODE_NXDOMAIN || found == 0)
        return RESP_NOTFOUND;

    walkRecords(resp, resp_len, records, hdr.num_ans_rr, total, 1, auth, &found, err, err_len);
    return RESP_ANSWERS;
}
