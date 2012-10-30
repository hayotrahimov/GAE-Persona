#!/usr/bin/env python

"""
The MIT License

Copyright (c) 2012 Peter Lieberwirth

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import os
import logging
import sys
import traceback
import urllib
import urllib2
import json
import datetime

import webapp2
from webapp2_extras import sessions
from webapp2_extras import sessions_ndb

os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

from google.appengine.ext.webapp import template
from google.appengine.api import users

import settings
from utilities import is_testenv

logging.info('Loading %s, app version = %s', __name__, os.getenv('CURRENT_VERSION_ID'))


def user_required(handler):
    """
        Decorator for checking if there's a user associated with the current session.
        Will also fail if there's no session present.
        Redirects to login page (/login) if no user or session
    """

    def check_login(self, *args, **kwargs):
        try:
            currentUser = self.session['currentUser']
        except Exception:
            # logging.debug('check_login did not find currentUser')
            # we do not have a session yet.  go to login page
            self.redirect('/login')
        else:
            # todo: now self.session.clear() on logout is called, so maybe don't need this next chunk
            if currentUser == None:
                self.redirect('/login')
            else:
                return handler(self, *args, **kwargs)

    return check_login


class BaseRequestHandler(webapp2.RequestHandler):
    """ Catch any exceptions and log them, including traceback
        todo: need to execute super if debug, and also todo: need to display error page to user
        All other request handlers here inherit from this base class.

        todo: take advantage of webapp2 exception goodies.
        """

    def __init__(self, request, response):
        """ webapp2 needs these reset each handler invoication"""

        self.initialize(request, response)
        logging.getLogger().setLevel(logging.DEBUG)
        os.environ["DJANGO_SETTINGS_MODULE"] = "settings"

    # webapp2 sessions
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a database session (using default cookie?)
        return self.session_store.get_session(name='db_session',
            factory=sessions_ndb.DatastoreSessionFactory)

    def head(self, *args):
        """Head is used by Twitter. If not used the tweet button shows 0"""
        pass

    def template_path(self, filename):
        """Returns the full path for a template from its path relative to here."""
        return os.path.join(os.path.dirname(__file__), filename)

    def render_to_response(self, filename, template_args):
        """Renders a Django template and sends it to the client.

        Args:
          filename: template path (relative to this file)
          template_args: argument dict for the template

        """

        # Preset values for the template (thanks to metachris for the inspiration)
        #
        values = {
            'request': self.request,
            'current_uri': self.request.uri,
            'login_url': users.create_login_url(self.request.uri),
            'logout_url': users.create_logout_url(self.request.uri),
        }

        # Add manually supplied template values
        values.update(template_args)
        self.response.out.write(
            template.render(self.template_path(filename), template_args)
        )

    def render_error(self, errormsg, usermsg='Application Error'):
        """Logs the error, renders the error page template, and sends it to the client. """
        self.render_to_response('templates/errors.html',
            {'errormsg': errormsg, 'usermsg': usermsg})

    def handle_exception(self, exception, debug_mode):
        # todo: this can probably be seriously cleaned up.
        template_values = {}
        exception_name = sys.exc_info()[0].__name__
        exception_details = str(sys.exc_info()[1])
        exception_traceback = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.error('Exception: %s ' % exception_name)
        logging.error('Exception Details: %s ' % exception_details)
        logging.error(exception_traceback)
        if users.is_current_user_admin() or is_testenv():
            template_values['traceback'] = exception_traceback
        self.response.out.write(template.render('templates/errors.html',
                                                template_values))


class HomeHandler(BaseRequestHandler):
    """   Simple Home Page """

    def get(self):
        """ / """

        currentUser = None
        try:
            currentUser = self.session['currentUser']
        except Exception:
            # keyerror, no session, no currentUser
            currentUser = None

        if currentUser:
            return self.render_to_response('templates/results.html',
                {'currentUser': self.session['currentUser'],
                'issuer': self.session['issuer'],
                'expires': self.session['expires'],
                'date': self.session['date'],
                'audience': urllib2.Request(self.request.url).get_host()
                })
        else:
            self.render_to_response('templates/home.html',
                {'currentUser': currentUser})


class LoginHandler(BaseRequestHandler):
    """ Display the login page"""

    def get(self):
        raise NotImplementedError

    def post(self):
        """  Mozilla Persona login handler

          aka browserid
          see: https://developer.mozilla.org/en-US/docs/Persona

          note, this is useful for testing:
          https://mockmyid.com/  """

        # logging.debug('Persona Login Handler AKA /login POST')
        # logging.debug('PERSONA ASSERTION AND AUDIENCE')
        # logging.debug('---assertion: %s' % self.request.get('assertion'))
        # logging.debug('---audience: %s' % urllib2.Request(self.request.url).get_host())

        data = {
            "assertion": self.request.get('assertion'),
            "audience": urllib2.Request(self.request.url).get_host()
        }

        try:
            req = urllib2.Request('https://browserid.org/verify', urllib.urlencode(data))
            json_result = urllib2.urlopen(req).read()
        except Exception, e:
            logging.error(e)
            raise RuntimeError('Persona Verification Failed')

        # Parse the JSON to extract the e-mail, store user in session
        result = json.loads(json_result)
        # logging.debug('Persona Verify Result')
        # logging.debug(result)
        if result.get('status') == 'okay':
            userEmail = result.get('email')
            self.session['currentUser'] = userEmail
            self.session['issuer'] = result.get('issuer')
            self.session['expires'] = result.get('expires')
            self.session['date'] = datetime.datetime.fromtimestamp(result.get('expires') / 1000)
            # logging.debug('created this session:')
            # logging.debug(self.session)
        else:
            return self.render_error(errormsg='Persona verification result error status is %s'
                % result.get('status'),
                usermsg='Authentication Problem')

        # todo: save user in datastore here?  or not....
        logging.info('%s logged in via %s' % (userEmail, result.get('issuer')))


class PersonaLogoutHandler(BaseRequestHandler):
    """
        Destroy session and redirect to home page
    """
    @user_required
    def post(self):
        logging.info('Logging out %s' % self.session['currentUser'])
        self.session.clear()
        self.redirect('/')


apps_binding = []
apps_binding.append(('/', HomeHandler))
apps_binding.append(('/personalogout', PersonaLogoutHandler))
apps_binding.append(('/login', LoginHandler))

sess_config = {}
sess_config['webapp2_extras.sessions'] = {
    'secret_key': settings.SESSIONS_KEY
}

app = webapp2.WSGIApplication(apps_binding, debug=True, config=sess_config)
