#
# -*- coding: utf-8 -*-
# Wireshark tests
#
# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Helpers for matching test results.'''

import re

class MatchAny(object):
    '''Matches any other value.'''

    def __init__(self, type=None):
        self.type = type

    def __eq__(self, other):
        return self.type is None or self.type == type(other)

    def __repr__(self):
        return '<MatchAny type=%s>' % (self.type.__name__,)


class MatchObject(object):
    '''Matches all expected fields of an object, ignoring excess others.'''

    def __init__(self, fields):
        self.fields = fields

    def __eq__(self, other):
        return all(other.get(k) == v for k, v in self.fields.items())

    def __repr__(self):
        return '<MatchObject fields=%r>' % (self.fields,)


class MatchList(object):
    '''Matches elements of a list. Optionally checks list length.'''

    def __init__(self, item, n=None, match_element=all):
        self.item = item
        self.n = n
        self.match_element = match_element

    def __eq__(self, other):
        if self.n is not None and len(other) != self.n:
            return False
        return self.match_element(self.item == elm for elm in other)

    def __repr__(self):
        return '<MatchList item=%r n=%r match_element=%s>' % \
                (self.item, self.n, self.match_element.__name__)


class MatchRegExp(object):
    '''Matches a string against a regular expression.'''

    def __init__(self, pattern):
        self.pattern = pattern

    def __eq__(self, other):
        return type(other) == str and re.match(self.pattern, other)

    def __repr__(self):
        return '<MatchRegExp pattern=%r>' % (self.pattern)
