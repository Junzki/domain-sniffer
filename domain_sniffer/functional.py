# -*- coding: utf-8 -*-
#
# Copyright 2013-2015 clowwindy
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
import re
from typing import AnyStr


def compat_ord(s):
    if type(s) == int:
        return s
    return ord(s)


def compat_chr(d):
    if bytes == str:
        return chr(d)
    return bytes([d])


HOSTNAME_PATTERN = re.compile(br"(?!-)[A-Z\d\-_]{1,63}(?<!-)$", re.IGNORECASE)


def is_valid_hostname(hostname: AnyStr) -> bool:
    if len(hostname) > 255:
        return False

    if isinstance(hostname, str):
        hostname = hostname.encode()  # Cast to bytes.

    hostname = hostname.strip(b'.')
    return all(HOSTNAME_PATTERN.match(x) for x in hostname.split(b'.'))
