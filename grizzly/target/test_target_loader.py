# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
unittests for target plugin loading
"""

import pytest

from grizzly.target import available, load, Target


class _FakeTarget1(Target):  # pylint: disable=abstract-method
    pass


class _FakeTarget2(Target):  # pylint: disable=abstract-method
    pass


def test_target_load_01(mocker):
    '''If no targets are available, available() should return nothing.'''
    mocker.patch('grizzly.target.TARGETS', None)
    mocker.patch('grizzly.target.iter_entry_points', lambda _: [])
    assert not available()


def test_target_load_02(mocker):
    '''Loading targets works.'''
    mocker.patch('grizzly.target.TARGETS', None)

    class _FakeEntryPoint1(object):
        name = 'test1'

        @staticmethod
        def load():
            return _FakeTarget1

    class _FakeEntryPoint2(object):
        name = 'test2'

        @staticmethod
        def load():
            return _FakeTarget2

    mocker.patch('grizzly.target.iter_entry_points', lambda _: [_FakeEntryPoint1, _FakeEntryPoint2])
    assert set(available()) == {'test1', 'test2'}
    assert load('test1') is _FakeTarget1
    assert load('test2') is _FakeTarget2


def test_target_load_03(mocker):
    '''Non-Target will be skipped.'''
    mocker.patch('grizzly.target.TARGETS', None)

    class _FakeEntryPoint1(object):
        name = 'test1'

        @staticmethod
        def load():
            return Target

    class _FakeEntryPoint2(object):
        name = 'test2'

        @staticmethod
        def load():
            return object

    mocker.patch('grizzly.target.iter_entry_points', lambda _: [_FakeEntryPoint1, _FakeEntryPoint2])
    assert set(available()) == {'test1'}
    assert load('test1') is Target


def test_target_load_04(mocker):
    '''test load() with name collision'''
    mocker.patch('grizzly.target.TARGETS', None)

    class _FakeEntryPoint1(object):
        name = 'test'

        @staticmethod
        def load():
            return _FakeTarget1

    class _FakeEntryPoint2(object):
        name = 'test'

        @staticmethod
        def load():
            return _FakeTarget2

    mocker.patch('grizzly.target.iter_entry_points', lambda _: [_FakeEntryPoint1, _FakeEntryPoint2])
    with pytest.raises(RuntimeError, match=r"Target (.)test\1 already exists"):
        available()


def test_target_load_05(mocker):
    '''test load() with broken Target'''
    mocker.patch('grizzly.target.TARGETS', None)

    class _FakeEntryPoint1(object):
        name = 'test1'

        @staticmethod
        def load():
            return Target

    class _FakeEntryPoint2(object):
        name = 'test2'

        @staticmethod
        def load():
            raise Exception("boo!")

    mocker.patch('grizzly.target.iter_entry_points', lambda _: [_FakeEntryPoint1, _FakeEntryPoint2])
    assert set(available()) == {'test1'}
    assert load('test1') is Target
