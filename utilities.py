#!/usr/bin/env python

from os import environ


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
