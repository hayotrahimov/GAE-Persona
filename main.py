#!/usr/bin/env python
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

import os
import logging
import sys
import traceback
import urllib
import urllib2
import json

import webapp2
from webapp2_extras import sessions
from webapp2_extras import sessions_ndb

os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

from google.appengine.ext.webapp import template
from google.appengine.api import users
from google.appengine.api import xmpp
from google.appengine.ext.webapp import xmpp_handlers
from google.appengine.api import memcache

import settings
from utilities import decode
from utilities import is_testenv
from utilities import AppError

# Log a message each time this module get loaded.
# todo: add app minor version from settings
logging.info('Loading %s, app version = %s', __name__, os.getenv('CURRENT_VERSION_ID'))

try:
    status = xmpp.send_message(settings.CHAT_ADMIN, 'Awake.')
except Exception, e:
    logging.warning('Failed to send XMPP startup message')
    memcache.incr('error_ctr')
    logging.warning(e)


# Init counters for xmpp status, memcache only, these provide only an indicative snapshot for well-being check
memcache.set_multi(
    {
        'admin_ctr': 0,
        'about_ctr': 0,
        'home_ctr': 0,
        'no_results_ctr': 0,
        'error_ctr': 0,
        'last_error_message': 'None',
        'last_query': 'None'
    }
)


class TestException(AppError):
    pass


def user_required(handler):
    """
        Decorator for checking if there's a user associated with the current session.
        Will also fail if there's no session present.
        Redirects to login page (/login) if no user or session
    """
    # logging.debug('user_required')

    def check_login(self, *args, **kwargs):
        try:
            currentUser = self.session['currentUser']
        except Exception:
            # logging.debug('check_login did not find currentUser')
            # we do not have a session yet.  go to login page
            self.redirect('/login')
        else:
            # todo: now that i do self.session.clear() on logout I think i don't need this next chunk
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
        return self.session_store.get_session(name='db_session', factory=sessions_ndb.DatastoreSessionFactory)

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
        self.render_to_response('templates/errors.html', {'usermsg': usermsg})

    def handle_exception(self, exception, debug_mode):
        # todo: this can probably be seriously cleaned up.
        template_values = {}
        exception_name = sys.exc_info()[0].__name__
        exception_details = str(sys.exc_info()[1])
        exception_traceback = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.error('Exception: %s ' % exception_name)
        logging.error('Exception Details: %s ' % exception_details)
        logging.debug(exception_traceback)
        xmpp.send_message(settings.CHAT_ADMIN, 'Exception! %s ' % exception_name)
        if users.is_current_user_admin() or is_testenv():
            template_values['traceback'] = exception_traceback
        self.response.out.write(template.render('templates/errors.html',
                                                template_values))


class CmdBotHandler(xmpp_handlers.CommandHandler):
    """ xmpp handler to reply to admin commands.  this is a bot.  """

    def status_command(self, message):
        frm = decode(self.request.get('from'))
        to = decode(self.request.get('to'))
        body = decode(self.request.get('body'))
        logging.info('CmdBot received status command: from %s, to %s ' % (frm, to))
        if body:
            logging.debug('CmdBot received message body: %s ' % body)

        # todo: fix this, display counters.  APIs. Pages.  Errors.  use memcache.get_multi()
        msg = 'Listening.'
        # logging.info('CmdBot %s ' % msg)
        message.reply(msg)

    def fail_command(self, message):
        """ set up to test exception handling """

        frm = decode(self.request.get('from'))
        to = decode(self.request.get('to'))
        logging.warning('CmdBot received fail command from: %s, to %s ' % (frm, to))

        raise TestException

    def query_command(self, message):
        """ reply with latest query, if there is one"""

        # frm = cgi.escape(self.request.get('from'))
        # to = cgi.escape(self.request.get('to'))
        # logging.info('CmdBot received query command from: %s, to %s ' % (frm, to))

        last_query = memcache.get('last_query')
        if last_query is not None:
            message.reply(last_query)
        else:
            message.reply('No query in memcache.')


class AboutHandler(BaseRequestHandler):
    """ render the about page """

    def get(self):
        logging.debug('AboutHandler')
        memcache.incr('about_ctr')

        try:
            currentUser = self.session['currentUser']
        except Exception:
            # keyerror, no session, no currentUser
            currentUser = None

        self.render_to_response('templates/home.html',
            {'none': None, 'currentUser': currentUser})


class HomeHandler(BaseRequestHandler):
    """ Simple home page - just display form for query string

    """

    def get(self):
        """ render simple home page"""

        logging.debug('HomeHandler, Get')
        memcache.incr('home_ctr')

        try:
            currentUser = self.session['currentUser']
        except Exception:
            # keyerror, no session, no currentUser
            currentUser = None

        self.render_to_response('templates/home.html',
            {'none': None, 'currentUser': currentUser})


class LoginHandler(BaseRequestHandler):
    """ Display the login page"""

    def get(self):

        logging.debug('Login Handler')

        # todo: too much repeated code here, clean up
        try:
            currentUser = self.session['currentUser']
        except Exception:
            # keyerror, no session, no currentUser
            currentUser = None

        # todo: now that i do self.session.clear() on logout I think i don't need this next chunk
        if currentUser == None:
            # no user, display the login page
            self.render_to_response('templates/login.html',
                {'query': None, 'currentUser': currentUser})
        else:
            logging.warning('%s already logged in' % currentUser)  # todo - make this a message
            self.redirect('/')

    def post(self):
        """  Mozilla Persona login handler

          aka browserid
          see: https://developer.mozilla.org/en-US/docs/Persona

          note, this is useful for testing:
          https://mockmyid.com/

        """

        logging.debug('Persona Login Handler AKA /login POST')
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
            logging.debug('System error verifying Persona credentials.')
            logging.error(e)
            raise AppError('Failure during Persona Verification')

        # Parse the JSON to extract the e-mail, store user in session
        result = json.loads(json_result)
        logging.debug('Persona Verify Result')
        logging.debug(result)
        if result.get('status') == 'okay':
            userEmail = result.get('email')
            self.session['currentUser'] = userEmail
            self.session['issuer'] = result.get('issuer')
            self.session['expires'] = result.get('expires')
            self.session['provider'] = 'Mozilla Persona'
            # logging.debug('created this session:')
            # logging.debug(self.session)
        else:
            return self.render_error(errormsg='Persona verification result error status is %s' % result.get('status'),
                usermsg='Authentication Problem')

        # todo: save user in datastore here?  or not....
        # optionally, check email against approved list and kick out if failure.  registration flow?
        logging.info('%s logged in via %s' % (userEmail, result.get('issuer')))

        self.redirect('/')


class PersonaLogoutHandler(BaseRequestHandler):
    """
        Destroy session and redirect to home page
    """
    @user_required
    def post(self):
        logging.debug('Persona Logout Handler')
        logging.info('Logging out %s' % self.session['currentUser'])
        self.session.clear()
        self.redirect('/')


class AdminHandler(BaseRequestHandler):
    """ Simple interface to admin stats and actions """

    @user_required
    def get(self):
        logging.debug('AdminHandler Get')
        memcache.incr('admin_ctr')

        # verify is admin?  how to do this?  vs google accounts.
        counters = memcache.get_multi(
            (
            'admin_ctr',
            'about_ctr',
            'home_ctr',
            'error_ctr',
            'no_results_ctr'
            )
        )

        stats = memcache.get_stats()

        # todo: add cached error string(s) and display in errors.

        self.render_to_response('templates/admin.html',
            {'counters': counters, 'stats': stats,
            'errors': 'TBD', 'currentUser': self.session['currentUser']}
        )


class NewPageHandler(BaseRequestHandler):
    """
        Just a template page
    """
    @user_required
    def get(self):
        self.render_to_response('templates/new_page.html',
            {'none': None, 'currentUser': self.session['currentUser']})


class AFormHandler(BaseRequestHandler):
    """
        Sample Page with a form
        todo: add a modal example.
    """

    @user_required
    def get(self):
        self.render_to_response('templates/a_form.html',
            {'none': None, 'currentUser': self.session['currentUser']}
        )

    @user_required
    def post(self):
        """ render a results page """

        logging.debug('AFormHandler, Post')
        query = decode(self.request.get('query'))

        self.render_to_response('templates/results.html',
            {'query': query, 'currentUser': self.session['currentUser']}
        )


apps_binding = []

apps_binding.append(('/', HomeHandler))
apps_binding.append(('/about', AboutHandler))
apps_binding.append(('/admin', AdminHandler))
apps_binding.append(('/personalogout', PersonaLogoutHandler))
apps_binding.append(('/login', LoginHandler))
apps_binding.append(('/newpage', NewPageHandler))
apps_binding.append(('/aform', AFormHandler))

apps_binding.append(('/_ah/xmpp/message/chat/', CmdBotHandler))

sess_config = {}
sess_config['webapp2_extras.sessions'] = {
    'secret_key': settings.SESSIONS_KEY
}

app = webapp2.WSGIApplication(apps_binding, debug=True, config=sess_config)
