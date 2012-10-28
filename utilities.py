# -*- coding: utf-8 -*-
#
# Copyright 2007 Google Inc.
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
#

__author__ = 'Identity Associates LLC'

import re
import unicodedata
from os import environ


class AppError(Exception):
    """ application exception"""

    def __init__(self, reason, response=None):
        self.reason = str(reason)
        self.response = response

    def __str__(self):
        return self.reason


def is_testenv():
    """
    True if devserver, False if appengine server

    Appengine uses 'Google App Engine/<version>',
    Devserver uses 'Development/<version>'
    """
    return environ.get('SERVER_SOFTWARE', '').startswith('Development')


def decode(var):
    """Safely decode form input"""
    if not var:
        return var
    return unicode(var, 'utf-8') if isinstance(var, str) else unicode(var)


def slugify(value):
    """
    Normalizes string, converts to lowercase, removes non-ascii characters,
    and converts spaces to hyphens.

    From Django's "django/template/defaultfilters.py".
    """
    _slugify_strip_re = re.compile(r'[^\w\s-]')
    _slugify_hyphenate_re = re.compile(r'[-\s]+')

    if not isinstance(value, unicode):
        value = unicode(value)
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore')
    value = unicode(_slugify_strip_re.sub('', value).strip().lower())
    return _slugify_hyphenate_re.sub('-', value)
