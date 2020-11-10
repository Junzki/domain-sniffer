# -*- coding: utf-8 -*-
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

import unittest
import time
from domain_sniffer.lru_cache import LRUCache


class TestLRUCache(unittest.TestCase):

    def setUp(self):
        self.close_cb_called = False

    def close_cb(self, t):
        assert not self.close_cb_called
        self.close_cb_called = True

    def test_lru_cache(self):
        c = LRUCache(timeout=0.3)

        c['a'] = 1
        assert c['a'] == 1

        time.sleep(0.5)
        c.sweep()
        assert 'a' not in c

        c['a'] = 2
        c['b'] = 3
        time.sleep(0.2)
        c.sweep()
        assert c['a'] == 2
        assert c['b'] == 3

        time.sleep(0.2)
        c.sweep()
        c['b']
        time.sleep(0.2)
        c.sweep()
        assert 'a' not in c
        assert c['b'] == 3

        time.sleep(0.5)
        c.sweep()
        assert 'a' not in c
        assert 'b' not in c

    def test_lru_cache_callback(self):
        c = LRUCache(timeout=0.1, close_callback=self.close_cb)
        c['s'] = 1
        c['t'] = 1
        c['s']
        time.sleep(0.1)
        c['s']
        time.sleep(0.3)
        c.sweep()
