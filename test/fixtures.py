#
# -*- coding: utf-8 -*-
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

_use_native_pytest = False


def enable_pytest():
    global _use_native_pytest, pytest
    assert not _fallback
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


# Begin fallback functionality when pytest is not available.
# Supported:
# - session-scoped fixtures (for cmd_tshark)
# - function-scoped fixtures (for tmpfile)
# - teardown (via yield keyword in fixture)
# - sorting of scopes (session before function)
# - fixtures that depend on other fixtures (requires sorting)
# - marking classes with @pytest.mark.usefixtures("fixture")
# Not supported (yet) due to lack of need for it:
# - autouse fixtures
# - parameterized fixtures (@pytest.fixture(params=...))
# - class-scoped fixtures
# - (overriding) fixtures on various levels (e.g. conftest, module, class)


class _FixtureSpec(object):
    def __init__(self, name, scope, func):
        self.name = name
        self.scope = scope
        self.func = func
        self.params = inspect.getfullargspec(func).args
        if inspect.ismethod(self.params):
            self.params = self.params[1:]  # skip self

    def __repr__(self):
        return '<_FixtureSpec name=%s scope=%s params=%r>' % \
            (self.name, self.scope, self.params)


class _FixturesManager(object):
    '''Records collected fixtures when pytest is unavailable.'''
    fixtures = {}
    # supported scopes, in execution order.
    SCOPES = ('session', 'function')

    def _add_fixture(self, scope, autouse, name, func):
        name = name or func.__name__
        if name in self.fixtures:
            raise NotImplementedError('overriding fixtures is not supported')
        self.fixtures[name] = _FixtureSpec(name, scope, func)
        return func

    def fixture(self, scope, params, autouse, ids, name):
        if params:
            raise NotImplementedError('params is not supported')
        if ids:
            raise NotImplementedError('ids is not supported')
        if autouse:
            raise NotImplementedError('autouse is not supported yet')

        if callable(scope):
            # used as decorator, pass through the original function
            self._add_fixture('function', autouse, name, scope)
            return scope
        assert scope in self.SCOPES, 'unsupported scope'
        # invoked with arguments, should return a decorator
        return lambda func: self._add_fixture(scope, autouse, name, func)

    def lookup(self, name):
        return self.fixtures.get(name)

    def resolve_fixtures(self, fixtures):
        '''Find all dependencies for the requested list of fixtures.'''
        unresolved = fixtures.copy()
        resolved_keys, resolved = [], []
        while unresolved:
            param = unresolved.pop(0)
            if param in resolved:
                continue
            spec = self.lookup(param)
            if not spec:
                if param == 'request':
                    continue
                raise RuntimeError("Fixture '%s' not found" % (param,))
            unresolved += spec.params
            resolved_keys.append(param)
            resolved.append(spec)
        # Return fixtures, sorted by their scope
        resolved.sort(key=lambda spec: self.SCOPES.index(spec.scope))
        return resolved


class _ExecutionScope(object):
    '''Store execution/teardown state for a scope.'''

    def __init__(self, scope, parent):
        self.scope = scope
        self.parent = parent
        self.cache = {}
        self.finalizers = []

    def _find_scope(self, scope):
        context = self
        while context.scope != scope:
            context = context.parent
        return context

    def execute(self, spec, test_fn):
        '''Execute a fixture and cache the result.'''
        context = self._find_scope(spec.scope)
        if spec.name in context.cache:
            return
        try:
            value, cleanup = self._execute_one(spec, test_fn)
            exc = None
        except Exception:
            value, cleanup, exc = None, None, sys.exc_info()[1]
        context.cache[spec.name] = value, exc
        if cleanup:
            context.finalizers.append(cleanup)
        if exc:
            raise exc

    def cached_result(self, spec):
        '''Obtain the cached result for a previously executed fixture.'''
        entry = self._find_scope(spec.scope).cache.get(spec.name)
        if not entry:
            return None, False
        value, exc = entry
        if exc:
            raise exc
        return value, True

    def _execute_one(self, spec, test_fn):
        # A fixture can only execute in the same or earlier scopes
        context_scope_index = _FixturesManager.SCOPES.index(self.scope)
        fixture_scope_index = _FixturesManager.SCOPES.index(spec.scope)
        assert fixture_scope_index <= context_scope_index
        if spec.params:
            # Do not invoke destroy, it is taken care of by the main request.
            subrequest = _FixtureRequest(self)
            subrequest.function = test_fn
            subrequest.fillfixtures(spec.params)
            fixtures = (subrequest.getfixturevalue(n) for n in spec.params)
            value = spec.func(*fixtures)  # Execute fixture
        else:
            value = spec.func()  # Execute fixture
        if not inspect.isgenerator(value):
            return value, None

        @functools.wraps(value)
        def cleanup():
            try:
                next(value)
            except StopIteration:
                pass
            else:
                raise RuntimeError('%s yielded more than once!' % (spec.name,))
        return next(value), cleanup

    def destroy(self):
        exceptions = []
        for cleanup in self.finalizers:
            try:
                cleanup()
            except:
                exceptions.append(sys.exc_info()[1])
        self.cache.clear()
        self.finalizers.clear()
        if exceptions:
            raise exceptions[0]


class _FixtureRequest(object):
    '''
    Holds state during a single test execution. See
    https://docs.pytest.org/en/latest/reference.html#request
    '''

    def __init__(self, context):
        self._context = context
        self._fixtures_prepend = []  # fixtures added via usefixtures
        # XXX is there any need for .module or .cls?
        self.function = None  # test function, set before execution.

    def fillfixtures(self, params):
        params = self._fixtures_prepend + params
        specs = _fallback.resolve_fixtures(params)
        for spec in specs:
            self._context.execute(spec, self.function)

    def getfixturevalue(self, argname):
        spec = _fallback.lookup(argname)
        if not spec:
            assert argname == 'request'
            return self
        value, ok = self._context.cached_result(spec)
        if not ok:
            # If getfixturevalue is called directly from a setUp function, the
            # fixture value might not have computed before, so evaluate it now.
            # As the test function is not available, use None.
            self._context.execute(spec, test_fn=None)
            value, ok = self._context.cached_result(spec)
            assert ok, 'Failed to execute fixture %s' % (spec,)
        return value

    def destroy(self):
        self._context.destroy()

    def addfinalizer(self, finalizer):
        self._context.finalizers.append(finalizer)

    @property
    def instance(self):
        return self.function.__self__

    @property
    def config(self):
        '''The pytest config object associated with this request.'''
        return _config


def _patch_unittest_testcase_class(cls):
    '''
    Patch the setUp and tearDown methods of the unittest.TestCase such that the
    fixtures are properly setup and destroyed.
    '''

    def setUp(self):
        assert _session_context, 'must call create_session() first!'
        function_context = _ExecutionScope('function', _session_context)
        req = _FixtureRequest(function_context)
        req._fixtures_prepend = getattr(self, '_fixtures_prepend', [])
        self._fixture_request = req
        self._orig_setUp()

    def tearDown(self):
        try:
            self._orig_tearDown()
        finally:
            self._fixture_request.destroy()
    # Only the leaf test case class should be decorated!
    assert not hasattr(cls, '_orig_setUp')
    assert not hasattr(cls, '_orig_tearDown')
    cls._orig_setUp, cls.setUp = cls.setUp, setUp
    cls._orig_tearDown, cls.tearDown = cls.tearDown, tearDown


class _Config(object):
    def __init__(self, args):
        assert isinstance(args, argparse.Namespace)
        self.args = args

    def getoption(self, name, default):
        '''Partial emulation for pytest Config.getoption.'''
        name = name.lstrip('-').replace('-', '_')
        return getattr(self.args, name, default)


_fallback = None
_session_context = None
_config = None


def init_fallback_fixtures_once():
    global _fallback
    assert not _use_native_pytest
    if _fallback:
        return
    _fallback = _FixturesManager()
    # Register standard fixtures here as needed


def create_session(args=None):
    '''Start a test session where args is from argparse.'''
    global _session_context, _config
    assert not _use_native_pytest
    _session_context = _ExecutionScope('session', None)
    if args is None:
        args = argparse.Namespace()
    _config = _Config(args)


def destroy_session():
    global _session_context
    assert not _use_native_pytest
    _session_context = None


def skip(msg):
    '''Skip the executing test with the given message.'''
    if _use_native_pytest:
        pytest.skip(msg)
    else:
        raise unittest.SkipTest(msg)
