# -*- coding:utf-8 -*-
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import os
import socket
import struct
from dataclasses import dataclass
from typing import AnyStr, List, Optional
from domain_sniffer.functional import compat_chr, compat_ord

BUFFER_SIZE = 4096

DNS_DEFAULT_SERVER = '1.1.1.1'
DNS_DEFAULT_PORT = 53

QTYPE_ANY = 255
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_MX = 15
QTYPE_AAAA = 28

QTYPE_MAP = {
    b'A': QTYPE_A,
    b'NS': QTYPE_NS,
    b'CNAME': QTYPE_CNAME,
    b'MX': QTYPE_MX,
    b'AAAA': QTYPE_AAAA,
    b'ANY': QTYPE_ANY
}


def qtype_aton(src: AnyStr) -> int:
    src_ = src  # Copy value
    if isinstance(src_, str):
        src_ = src_.encode()

    src_ = src_.upper()
    try:
        return QTYPE_MAP[src_]
    except KeyError:
        raise ValueError(f'QTYPE {src} not supported.')


QCLASS_IN = 1


@dataclass
class DnsRR:
    addr: bytes
    qtype: int = QTYPE_A
    qclass: int = QCLASS_IN

    def serialize(self) -> bytes:
        request_id = os.urandom(2)
        header = struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)
        addr = self.serialize_addr()
        qtype_qclass = struct.pack('!HH', self.qtype, self.qclass)
        return request_id + header + addr + qtype_qclass

    def serialize_addr(self) -> bytes:
        addr = self.addr.strip(b'.')
        labels = addr.split(b'.')
        results = list()
        for label in labels:
            size = len(label)
            if size > 63:
                raise ValueError('Hostname too large, should not larger than 63 bytes.')

            results.append(compat_chr(size))
            results.append(label)

        results.append(b'\0')
        return b''.join(results)


@dataclass
class Response(object):
    hostname: Optional[AnyStr] = None
    questions: Optional[List[DnsRR]] = None
    answers: Optional[List[DnsRR]] = None
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not self.questions:
            self.questions = list()

        if not self.answers:
            self.answers = list()

    def __str__(self):
        return '%s: %s' % (self.hostname, str(self.answers))


def parse_ip(addr_type, data, length, offset):
    if addr_type == QTYPE_A:
        return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])
    elif addr_type == QTYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + length])
    elif addr_type in [QTYPE_CNAME, QTYPE_NS]:
        return parse_name(data, offset)[1]
    else:
        return data[offset:offset + length]


def parse_name(data, offset):
    p = offset
    labels = []
    l = compat_ord(data[p])
    while l > 0:
        if (l & (128 + 64)) == (128 + 64):
            # pointer
            pointer = struct.unpack('!H', data[p:p + 2])[0]
            pointer &= 0x3FFF
            r = parse_name(data, pointer)
            labels.append(r[1])
            p += 2
            # pointer is the end
            return p - offset, b'.'.join(labels)
        else:
            labels.append(data[p + 1:p + 1 + l])
            p += 1 + l
        l = compat_ord(data[p])
    return p - offset + 1, b'.'.join(labels)


def parse_record(data, offset, question=False):
    nlen, name = parse_name(data, offset)
    if not question:
        record_type, record_class, record_ttl, record_rdlength = struct.unpack(
            '!HHiH', data[offset + nlen:offset + nlen + 10]
        )
        ip = parse_ip(record_type, data, record_rdlength, offset + nlen + 10)
        return nlen + 10 + record_rdlength, \
            (name, ip, record_type, record_class, record_ttl)
    else:
        record_type, record_class = struct.unpack(
            '!HH', data[offset + nlen:offset + nlen + 4]
        )
        return nlen + 4, (name, None, record_type, record_class, None, None)


def parse_header(data):
    if len(data) < 12:
        return None

    header = struct.unpack('!HBBHHHH', data[:12])
    res_id = header[0]
    res_qr = header[1] & 128
    res_tc = header[1] & 2
    res_ra = header[2] & 128
    res_rcode = header[2] & 15

    res_qdcount = header[3]
    res_ancount = header[4]
    res_nscount = header[5]
    res_arcount = header[6]
    return (res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount,
            res_ancount, res_nscount, res_arcount)


def parse_response(data) -> Response:
    if len(data) >= 12:
        header = parse_header(data)
        if not header:
            raise ValueError('No header parsed from response octets.')

        res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount, \
            res_ancount, res_nscount, res_arcount = header

        qds = []
        ans = []
        offset = 12
        for i in range(0, res_qdcount):
            l, r = parse_record(data, offset, True)
            offset += l
            if r:
                qds.append(r)
        for i in range(0, res_ancount):
            l, r = parse_record(data, offset)
            offset += l
            if r:
                ans.append(r)
        for i in range(0, res_nscount):
            l, r = parse_record(data, offset)
            offset += l
        for i in range(0, res_arcount):
            l, r = parse_record(data, offset)
            offset += l

        response = Response()
        if qds:
            response.hostname = qds[0][0]

        for an in qds:
            response.questions.append(DnsRR(an[1], an[2], an[3]))

        for an in ans:
            response.answers.append(DnsRR(an[1], an[2], an[3]))
        return response


def resolve(hostname: AnyStr,
            qtype: AnyStr = 'A',
            server: str = DNS_DEFAULT_SERVER,
            port: int = DNS_DEFAULT_PORT) -> Response:
    qtype = qtype_aton(qtype)
    req = DnsRR(addr=hostname, qtype=qtype)

    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.SOL_UDP)
    conn.sendto(req.serialize(), (server, port))
    data, addr = conn.recvfrom(BUFFER_SIZE)
    conn.close()

    if addr[0] != server:
        raise ValueError(f'Bad packet from {addr[0]}')

    res = parse_response(data)
    return res


if __name__ == '__main__':
    res_ = resolve(b'baidu.com')
    print(res_)
