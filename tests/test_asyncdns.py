# -*- coding:utf-8 -*-
#
# Copyright 2014-2015 clowwindy
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

from unittest import TestCase
from domain_sniffer.asyncdns import DNSResolver
from domain_sniffer.eventloop import EventLoop


class TestAsyncDNS(TestCase):

    def setUp(self) -> None:
        self.counter = 0
        self.dns_resolver = DNSResolver()
        self.loop = EventLoop()
        self.dns_resolver.add_to_loop(self.loop)

    def make_callback(self):
        def callback(result, error):
            print(result, error)
            self.counter += 1
            if self.counter == 9:
                self.dns_resolver.close()
                self.loop.stop()

        return callback
    
    def test_resolve(self):
        self.dns_resolver.resolve(b'google.com', self.make_callback())
        self.dns_resolver.resolve('google.com', self.make_callback())
        self.dns_resolver.resolve('example.com', self.make_callback())
        self.dns_resolver.resolve('ipv6.google.com', self.make_callback())
        self.dns_resolver.resolve('www.facebook.com', self.make_callback())
        self.dns_resolver.resolve('ns2.google.com', self.make_callback())
        self.dns_resolver.resolve('invalid.@!#$%^&$@.hostname', self.make_callback())
        self.dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  'long.hostname', self.make_callback())
        self.dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  'long.hostname', self.make_callback())

        self.loop.run()
