import socket
import struct
import sys


def header(qid, flags, qd=1, an=0, ns=0, ar=0):
    return struct.pack("!HHHHHH", qid, flags, qd, an, ns, ar)


def rr(name, rtype, rdata, rclass=1, ttl=300):
    return name + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def a_rec(ip, name=b"\xc0\x0c"):
    return rr(name, 1, socket.inet_aton(ip))


def encode(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


RESP = 0x8180
AUTH = 0x8580


def build(mode, query):
    qid = struct.unpack("!H", query[:2])[0]
    question = query[12:]
    qname_end = question.index(b"\x00") + 1
    qname = question[:qname_end]
    q = question[:qname_end + 4]

    if mode == "nodata":
        return [header(qid, RESP) + q]
    if mode == "short":
        return [query[:2] + b"\x81\x80\x00\x01\x00\x00"]
    if mode == "tc":
        return [header(qid, RESP | 0x0200) + q]
    if mode == "wrongid":
        return [header(qid ^ 0x1111, RESP, an=1) + q + a_rec("6.6.6.6"),
                header(qid, RESP, an=1) + q + a_rec("1.2.3.4")]
    if mode == "notresponse":
        return [header(qid, 0x0100, an=1) + q + a_rec("6.6.6.6"),
                header(qid, RESP, an=1) + q + a_rec("1.2.3.4")]
    if mode == "loop":
        start = 12 + len(q)
        return [header(qid, RESP, an=1) + q + struct.pack("!H", 0xC000 | start)
                + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton("1.2.3.4")]
    if mode == "forwardptr":
        return [header(qid, RESP, an=1) + q + b"\xc0\xff" + struct.pack("!HHIH", 1, 1, 300, 4)
                + socket.inet_aton("1.2.3.4")]
    if mode == "badalen":
        return [header(qid, RESP, an=1) + q + rr(b"\xc0\x0c", 1, b"\x01\x02\x03\x04\x05")]
    if mode == "overrun":
        return [header(qid, RESP, an=1) + q + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 40)
                + socket.inet_aton("1.2.3.4")]
    if mode == "trailing":
        return [header(qid, RESP, an=1) + q + a_rec("1.2.3.4") + b"\xde\xad"]
    if mode == "mismatch":
        return [header(qid, RESP, an=1) + encode("other.example") + q[qname_end:] + a_rec("1.2.3.4")]
    if mode == "noquestion":
        return [header(qid, RESP, qd=0, an=1) + a_rec("1.2.3.4", encode("x.example"))]
    if mode == "refused":
        return [header(qid, 0x8185) + q]
    if mode == "formerr":
        return [header(qid, 0x8181) + q]
    if mode == "rcode9":
        return [header(qid, 0x8189) + q]
    if mode == "chain":
        alias_off = 12 + len(q) + 12
        alias = b"\x05alias\x07example\x00"
        return [header(qid, RESP, an=3) + q
                + rr(b"\xc0\x0c", 5, alias)
                + rr(struct.pack("!H", 0xC000 | alias_off), 5, b"\x04next\xc0" + bytes([alias_off + 6]))
                + a_rec("9.9.9.9", b"\x04next" + struct.pack("!H", 0xC000 | (alias_off + 6)))]
    if mode == "otherport":
        return ["otherport", header(qid, RESP, an=1) + q + a_rec("1.2.3.4")]
    if mode == "silent":
        return []
    if mode == "mixed":
        return [header(qid, RESP, an=2) + q + rr(b"\xc0\x0c", 28, b"\x20\x01" + b"\x00" * 14)
                + a_rec("5.6.7.8")]
    if mode == "auth":
        return [header(qid, AUTH, an=1) + q + a_rec("10.0.0.1")]
    if mode == "many":
        return [header(qid, RESP, an=40) + q + b"".join(a_rec("10.1.0.%d" % i) for i in range(40))]
    if mode == "escaped":
        return [header(qid, RESP, an=1) + q + rr(b"\xc0\x0c", 5, b"\x03a.b\x01\x09\x07example\x00")]
    if mode == "upper":
        return [header(qid, RESP, an=1) + qname.upper() + q[qname_end:] + a_rec("1.2.3.4")]
    if mode == "authority":
        soa = rr(encode("example"), 6, encode("ns.example") + encode("admin.example")
                 + struct.pack("!IIIII", 1, 2, 3, 4, 5))
        return [header(qid, 0x8183, ns=1) + q + soa]
    if mode == "badclass":
        return [header(qid, RESP, an=1) + q + rr(b"\xc0\x0c", 1, socket.inet_aton("1.2.3.4"), rclass=3)]
    raise SystemExit("unknown mode " + mode)


def main():
    mode = sys.argv[1]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1], flush=True)
    sock.settimeout(10)
    query, client = sock.recvfrom(4096)
    for packet in build(mode, query):
        if packet == "otherport":
            other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            other.sendto(build("auth", query)[0], client)
            other.close()
            continue
        sock.sendto(packet, client)


main()
