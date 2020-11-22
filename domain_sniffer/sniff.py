# -*- coding:utf-8 -*-
from typing import Optional


SNIFF_MAP = {
    'http': ('A', 80),
    'https': ('A', 443)
}

DEFAULT_SNIFF_TYPE = 'http'
DEFAULT_SNIFF_TARGET = ('A', None)


def sniff(hostname: str,
          proto: str = DEFAULT_SNIFF_TYPE,
          port: Optional[int] = None):
    proto = proto.strip().lower()
    qtype, port_ = SNIFF_MAP.get(proto, DEFAULT_SNIFF_TARGET)

    port = port or port_
    if not port:
        raise ValueError('Sniff type not supported or port not specified.')

