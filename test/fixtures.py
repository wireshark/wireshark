#
# Extends unittest with support for pytest-style fixtures.
#
# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
#

import argparse
import functools
import inspect
import sys
import unittest

import pytest
_use_native_pytest = True


def fixture(callable_or_scope=None, *, scope="function", params=None,
            autouse=False, ids=None, name=None):
    """
    When running under pytest, this is the same as the pytest.fixture decorator.
    See https://docs.pytest.org/en/latest/reference.html#pytest-fixture
    """
    assert callable(callable_or_scope) or callable_or_scope is None, \
        'scope must be a keyword argument'
    if _use_native_pytest:
        if callable(callable_or_scope):
            return pytest.fixture(callable_or_scope)
        # XXX sorting of fixtures based on scope does not work, see
        # https://github.com/pytest-dev/pytest/issues/4143#issuecomment-431794076
        # When ran under pytest, use native functionality.
        return pytest.fixture(scope=scope, params=params, autouse=autouse,
                              ids=ids, name=name)
    init_fallback_fixtures_once()
    if callable(callable_or_scope):
        scope = callable_or_scope
    return _fallback.fixture(scope, params, autouse, ids, name)


def _fixture_wrapper(test_fn, params):
    @functools.wraps(test_fn)
    def wrapped(self):
        if not _use_native_pytest:
            self._fixture_request.function = getattr(self, test_fn.__name__)
            self._fixture_request.fillfixtures(params)
        fixtures = [self._fixture_request.getfixturevalue(n) for n in params]
        test_fn(self, *fixtures)
    return wrapped


def uses_fixtures(cls):
    """Enables use of fixtures within test methods of unittest.TestCase."""
    assert issubclass(cls, unittest.TestCase)

    for name in dir(cls):
        func = getattr(cls, name)
        if not name.startswith('test') or not callable(func):
            continue
        params = inspect.getfullargspec(func).args[1:]
        # Unconditionally overwrite methods in case usefixtures marks exist.
        setattr(cls, name, _fixture_wrapper(func, params))

    if _use_native_pytest:
        # Make request object to _fixture_wrapper
        @pytest.fixture(autouse=True)
        def __inject_request(self, request):
            self._fixture_request = request
        cls.__inject_request = __inject_request
    else:
        _patch_unittest_testcase_class(cls)

    return cls


def mark_usefixtures(*args):
    """Add the given fixtures to every test method."""
    if _use_native_pytest:
        return pytest.mark.usefixtures(*args)

    def wrapper(cls):
        cls._fixtures_prepend = list(args)
        return cls
    return wrapper

def skip(msg):
    '''Skip the executing test with the given message.'''
    pytest.skip(msg)
