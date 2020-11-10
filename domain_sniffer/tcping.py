# -*- coding:utf-8 -*-
#
# Copyright 2020 Andrew Junzki <andrew@junzki.me>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import socket
from dataclasses import dataclass
from .common import detect_address_family
from .eventloop import EventLoop


@dataclass
class PingResult:
    host: str
    port: int
    tried: int
    max: float
    min: float
    average: float


class TCPing(object):
    DEFAULT_TIMEOUT = 10

    def __init__(self, loop: EventLoop):
        self.loop = loop

    @staticmethod
    def do_ping(host: str,
                port: int,
                timeout: float = 10) -> float:
        address_family = detect_address_family(host)
        conn = socket.socket(address_family, socket.SOCK_STREAM)
        conn.setblocking(False)
        # conn.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 0)
        # conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 0)
        # conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        conn.settimeout(timeout)

        t1 = time.perf_counter_ns()
        conn.connect((host, port))
        conn.send(b'')
        conn.close()
        t2 = time.perf_counter_ns()

        t = (t2 - t1) / 1000.0  # Duration in microseconds.
        return t

    def ping(self,
             host: str,
             port: int,
             timeout: float = DEFAULT_TIMEOUT,
             retry: int = 3) -> PingResult:
        counter = 0
        results = list()
        while counter < retry:
            counter += 1
            d = self.do_ping(host, port, timeout)
            results.append(d)

        results = sorted(results)
        max_ = results[-1]
        min_ = results[0]

        avg_ = sum(results) / len(results)
        return PingResult(host=host, port=port, tried=counter+1,
                          max=max_, min=min_, average=avg_)
