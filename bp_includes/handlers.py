# -*- coding: utf-8 -*-
"""
    A real simple app for using webapp2 with auth and session.

    Routes are setup in routes.py and added in main.py
"""
# python imports
import logging
import json
import requests
from datetime import date, timedelta
import time

# appengine imports
import webapp2
from webapp2_extras import security
from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError
from webapp2_extras.i18n import gettext as _
from webapp2_extras.appengine.auth.models import Unique
from google.appengine.ext import ndb, blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.api import taskqueue, users, images
from google.appengine.api.datastore_errors import BadValueError
from google.appengine.runtime import apiproxy_errors

# local imports
import models, messages, forms
from github import github
from linkedin import linkedin
from lib import utils, captcha, twitter, facebook, bitly, myhtmlparser
from lib.cartodb import CartoDBAPIKey, CartoDBException
from lib.basehandler import BaseHandler
from lib.decorators import user_required, taskqueue_method



def captchaBase(self):
    if self.app.config.get('captcha_public_key') == "" or \
                    self.app.config.get('captcha_private_key') == "":
        chtml = '<div class="alert alert-danger"><strong>Error</strong>: You have to ' \
                '<a href="http://www.google.com/recaptcha/" target="_blank">sign up ' \
                'for API keys</a> in order to use reCAPTCHA.</div>' \
                '<input type="hidden" name="recaptcha_challenge_field" value="manual_challenge" />' \
                '<input type="hidden" name="recaptcha_response_field" value="manual_challenge" />'
    else:
        chtml = captcha.displayhtml(public_key=self.app.config.get('captcha_public_key'))
    return chtml



""" ACCOUNT handlers 

    These handlers include all classes concerning the login and logout interactions with users.

"""

class LoginRequiredHandler(BaseHandler):
    def get(self):
        continue_url = self.request.get_all('continue')
        self.redirect(users.create_login_url(dest_url=continue_url))

#original login handler
    # class LoginHandler(BaseHandler):
    #     """
    #     Handler for authentication
    #     """

    #     def get(self):
    #         """ Returns a simple HTML form for login """

    #         if self.user:
    #             self.redirect_to('home')
    #         params = {
    #             'captchahtml': captchaBase(self),
    #         }
    #         continue_url = self.request.get('continue').encode('ascii', 'ignore')
    #         params['continue_url'] = continue_url
    #         return self.render_template('login.html', **params)

    #     def post(self):
    #         """
    #         username: Get the username from POST dict
    #         password: Get the password from POST dict
    #         """

    #         if not self.form.validate():
    # 			_message = _(messages.post_error)
    # 			self.add_message(_message, 'danger')
    # 			return self.get()
    #         username = self.form.username.data.lower()
    #         continue_url = self.request.get('continue').encode('ascii', 'ignore')

    #         try:
    #             if utils.is_email_valid(username):
    #                 user = self.user_model.get_by_email(username)
    #                 if user:
    #                     auth_id = user.auth_ids[0]
    #                 else:
    #                     raise InvalidAuthIdError
    #             else:
    #                 auth_id = "own:%s" % username
    #                 user = self.user_model.get_by_auth_id(auth_id)
                
    #             password = self.form.password.data.strip()
    #             remember_me = True if str(self.request.POST.get('remember_me')) == 'on' else False

    #             # Password to SHA512
    #             password = utils.hashing(password, self.app.config.get('salt'))

    #             # Try to login user with password
    #             # Raises InvalidAuthIdError if user is not found
    #             # Raises InvalidPasswordError if provided password
    #             # doesn't match with specified user
    #             self.auth.get_user_by_password(
    #                 auth_id, password, remember=remember_me)

    #             # if user account is not activated, logout and redirect to home
    #             if (user.activated == False):
    #                 # logout
    #                 self.auth.unset_session()

    #                 # redirect to home with error message
    #                 resend_email_uri = self.uri_for('resend-account-activation', user_id=user.get_id(),
    #                                                 token=self.user_model.create_resend_token(user.get_id()))
    #                 message = _(messages.inactive_account) + ' ' + resend_email_uri
    #                 self.add_message(message, 'danger')
    #                 return self.redirect_to('login')
    #             else:
    #                 try:
    #                     user.last_login = utils.get_date_time()
    #                     user.put()
    #                 except (apiproxy_errors.OverQuotaError, BadValueError):
    #                     logging.error("Error saving Last Login in datastore")

    #             # check twitter association in session
    #             twitter_helper = twitter.TwitterAuth(self)
    #             twitter_association_data = twitter_helper.get_association_data()
    #             if twitter_association_data is not None:
    #                 if models.SocialUser.check_unique(user.key, 'twitter', str(twitter_association_data['id'])):
    #                     social_user = models.SocialUser(
    #                         user=user.key,
    #                         provider='twitter',
    #                         uid=str(twitter_association_data['id']),
    #                         extra_data=twitter_association_data
    #                     )
    #                     social_user.put()

    #             # check facebook association
    #             fb_data = None
    #             try:
    #                 fb_data = json.loads(self.session['facebook'])
    #             except:
    #                 pass

    #             if fb_data is not None:
    #                 if models.SocialUser.check_unique(user.key, 'facebook', str(fb_data['id'])):
    #                     social_user = models.SocialUser(
    #                         user=user.key,
    #                         provider='facebook',
    #                         uid=str(fb_data['id']),
    #                         extra_data=fb_data
    #                     )
    #                     social_user.put()

    #             # check linkedin association
    #             li_data = None
    #             try:
    #                 li_data = json.loads(self.session['linkedin'])
    #             except:
    #                 pass

    #             if li_data is not None:
    #                 if models.SocialUser.check_unique(user.key, 'linkedin', str(li_data['id'])):
    #                     social_user = models.SocialUser(
    #                         user=user.key,
    #                         provider='linkedin',
    #                         uid=str(li_data['id']),
    #                         extra_data=li_data
    #                     )
    #                     social_user.put()

    #             # end linkedin

    #             if self.app.config['log_visit']:
    #                 try:
    #                     logVisit = models.LogVisit(
    #                         user=user.key,
    #                         uastring=self.request.user_agent,
    #                         ip=self.request.remote_addr,
    #                         timestamp=utils.get_date_time()
    #                     )
    #                     logVisit.put()
    #                 except (apiproxy_errors.OverQuotaError, BadValueError):
    #                     logging.error("Error saving Visit Log in datastore")
    #             if continue_url:
    #                 self.redirect(continue_url)
    #             else:
    #                 self.redirect_to('home')
    #         except (InvalidAuthIdError, InvalidPasswordError), e:
    #             # Returns error message to self.response.write in
    #             # the BaseHandler.dispatcher
    #             message = _(messages.user_pass_mismatch)
    #             self.add_message(message, 'danger')
    #             self.redirect_to('login', continue_url=continue_url) if continue_url else self.redirect_to('login')

    #     @webapp2.cached_property
    #     def form(self):
    #         return forms.LoginForm(self)

class SocialLoginHandler(BaseHandler):
    """
    Handler for Social authentication
    """

    def get(self, provider_name):
        provider = self.provider_info[provider_name]

        if not self.app.config.get('enable_federated_login'):
            message = _('Federated login is disabled.')
            self.add_message(message, 'warning')
            return self.redirect_to('login')
        callback_url = "%s/social_login/%s/complete" % (self.request.host_url, provider_name)

        if provider_name == "twitter":
            twitter_helper = twitter.TwitterAuth(self, redirect_uri=callback_url)
            self.redirect(twitter_helper.auth_url())

        elif provider_name == "facebook":
            self.session['linkedin'] = None
            perms = ['email', 'publish_stream']
            self.redirect(facebook.auth_url(self.app.config.get('fb_api_key'), callback_url, perms))

        elif provider_name == 'linkedin':
            self.session['facebook'] = None
            authentication = linkedin.LinkedInAuthentication(
                self.app.config.get('linkedin_api'),
                self.app.config.get('linkedin_secret'),
                callback_url,
                [linkedin.PERMISSIONS.BASIC_PROFILE, linkedin.PERMISSIONS.EMAIL_ADDRESS])
            self.redirect(authentication.authorization_url)

        elif provider_name == "github":
            scope = 'gist'
            github_helper = github.GithubAuth(self.app.config.get('github_server'),
                                              self.app.config.get('github_client_id'), \
                                              self.app.config.get('github_client_secret'),
                                              self.app.config.get('github_redirect_uri'), scope)
            self.redirect(github_helper.get_authorize_url())

        elif provider_name in models.SocialUser.open_id_providers():
            continue_url = self.request.get('continue_url')
            if continue_url:
                dest_url = self.uri_for('social-login-complete', provider_name=provider_name, continue_url=continue_url)
            else:
                dest_url = self.uri_for('social-login-complete', provider_name=provider_name)
            try:
                login_url = users.create_login_url(federated_identity=provider['uri'], dest_url=dest_url)
                self.redirect(login_url)
            except users.NotAllowedError:
                self.add_message('You must enable Federated Login Before for this application.<br> '
                                 '<a href="http://appengine.google.com" target="_blank">Google App Engine Control Panel</a> -> '
                                 'Administration -> Application Settings -> Authentication Options', 'danger')
                self.redirect_to('login')

        else:
            message = _('%s authentication is not yet implemented.' % provider.get('label'))
            self.add_message(message, 'warning')
            self.redirect_to('login')

class CallbackSocialLoginHandler(BaseHandler):
    """
    Callback (Save Information) for Social Authentication
    """

    def get(self, provider_name):
        if not self.app.config.get('enable_federated_login'):
            message = _('Federated login is disabled.')
            self.add_message(message, 'warning')
            return self.redirect_to('login')
        continue_url = self.request.get('continue_url')
        if provider_name == "twitter":
            oauth_token = self.request.get('oauth_token')
            oauth_verifier = self.request.get('oauth_verifier')
            twitter_helper = twitter.TwitterAuth(self)
            user_data = twitter_helper.auth_complete(oauth_token,
                                                     oauth_verifier)
            logging.info('twitter user_data: ' + str(user_data))
            if self.user:
                # new association with twitter
                user_info = self.user_model.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, 'twitter', str(user_data['user_id'])):
                    social_user = models.SocialUser(
                        user=user_info.key,
                        provider='twitter',
                        uid=str(user_data['user_id']),
                        extra_data=user_data
                    )
                    social_user.put()

                    message = _('Twitter association added.')
                    self.add_message(message, 'success')
                else:
                    message = _('This Twitter account is already in use.')
                    self.add_message(message, 'danger')
                if continue_url:
                    self.redirect(continue_url)
                else:
                    self.redirect_to('edit-profile')
            else:
                # login with twitter
                social_user = models.SocialUser.get_by_provider_and_uid('twitter',
                                                                        str(user_data['user_id']))
                if social_user:
                    # Social user exists. Need authenticate related site account
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    if self.app.config['log_visit']:
                        try:
                            logVisit = models.LogVisit(
                                user=user.key,
                                uastring=self.request.user_agent,
                                ip=self.request.remote_addr,
                                timestamp=utils.get_date_time()
                            )
                            logVisit.put()
                        except (apiproxy_errors.OverQuotaError, BadValueError):
                            logging.error("Error saving Visit Log in datastore")
                    if continue_url:
                        self.redirect(continue_url)
                    else:
                        self.redirect_to('home')
                else:
                    uid = str(user_data['user_id'])
                    email = str(user_data.get('email'))
                    self.create_account_from_social_provider(provider_name, uid, email, continue_url, user_data)

        # github association
        elif provider_name == "github":
            # get our request code back from the social login handler above
            code = self.request.get('code')

            # create our github auth object
            scope = 'gist'
            github_helper = github.GithubAuth(self.app.config.get('github_server'),
                                              self.app.config.get('github_client_id'), \
                                              self.app.config.get('github_client_secret'),
                                              self.app.config.get('github_redirect_uri'), scope)

            # retrieve the access token using the code and auth object
            access_token = github_helper.get_access_token(code)
            user_data = github_helper.get_user_info(access_token)
            logging.info('github user_data: ' + str(user_data))
            if self.user:
                # user is already logged in so we set a new association with twitter
                user_info = self.user_model.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, 'github', str(user_data['login'])):
                    social_user = models.SocialUser(
                        user=user_info.key,
                        provider='github',
                        uid=str(user_data['login']),
                        extra_data=user_data
                    )
                    social_user.put()

                    message = _('Github association added.')
                    self.add_message(message, 'success')
                else:
                    message = _('This Github account is already in use.')
                    self.add_message(message, 'danger')
                self.redirect_to('edit-profile')
            else:
                # user is not logged in, but is trying to log in via github
                social_user = models.SocialUser.get_by_provider_and_uid('github', str(user_data['login']))
                if social_user:
                    # Social user exists. Need authenticate related site account
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    if self.app.config['log_visit']:
                        try:
                            logVisit = models.LogVisit(
                                user=user.key,
                                uastring=self.request.user_agent,
                                ip=self.request.remote_addr,
                                timestamp=utils.get_date_time()
                            )
                            logVisit.put()
                        except (apiproxy_errors.OverQuotaError, BadValueError):
                            logging.error("Error saving Visit Log in datastore")
                    self.redirect_to('home')
                else:
                    uid = str(user_data['id'])
                    email = str(user_data.get('email'))
                    self.create_account_from_social_provider(provider_name, uid, email, continue_url, user_data)
        #end github

        # facebook association
        elif provider_name == "facebook":
            code = self.request.get('code')
            callback_url = "%s/social_login/%s/complete" % (self.request.host_url, provider_name)
            token = facebook.get_access_token_from_code(code, callback_url, self.app.config.get('fb_api_key'),
                                                        self.app.config.get('fb_secret'))
            access_token = token['access_token']
            fb = facebook.GraphAPI(access_token)
            user_data = fb.get_object('me')
            logging.info('facebook user_data: ' + str(user_data))
            if self.user:
                # new association with facebook
                user_info = self.user_model.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, 'facebook', str(user_data['id'])):
                    social_user = models.SocialUser(
                        user=user_info.key,
                        provider='facebook',
                        uid=str(user_data['id']),
                        extra_data=user_data
                    )
                    social_user.put()

                    message = _('Facebook association added!')
                    self.add_message(message, 'success')
                else:
                    message = _('This Facebook account is already in use!')
                    self.add_message(message, 'danger')
                if continue_url:
                    self.redirect(continue_url)
                else:
                    self.redirect_to('edit-profile')
            else:
                # login with Facebook
                social_user = models.SocialUser.get_by_provider_and_uid('facebook',
                                                                        str(user_data['id']))
                if social_user:
                    # Social user exists. Need authenticate related site account
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    if self.app.config['log_visit']:
                        try:
                            logVisit = models.LogVisit(
                                user=user.key,
                                uastring=self.request.user_agent,
                                ip=self.request.remote_addr,
                                timestamp=utils.get_date_time()
                            )
                            logVisit.put()
                        except (apiproxy_errors.OverQuotaError, BadValueError):
                            logging.error("Error saving Visit Log in datastore")
                    if continue_url:
                        self.redirect(continue_url)
                    else:
                        self.redirect_to('home')
                else:
                    uid = str(user_data['id'])
                    email = str(user_data.get('email'))
                    self.create_account_from_social_provider(provider_name, uid, email, continue_url, user_data)

                    # end facebook
        # association with linkedin
        elif provider_name == "linkedin":
            callback_url = "%s/social_login/%s/complete" % (self.request.host_url, provider_name)
            authentication = linkedin.LinkedInAuthentication(
                self.app.config.get('linkedin_api'),
                self.app.config.get('linkedin_secret'),
                callback_url,
                [linkedin.PERMISSIONS.BASIC_PROFILE, linkedin.PERMISSIONS.EMAIL_ADDRESS])
            authentication.authorization_code = self.request.get('code')
            access_token = authentication.get_access_token()
            link = linkedin.LinkedInApplication(authentication)
            u_data = link.get_profile(selectors=['id', 'first-name', 'last-name', 'email-address'])
            user_data = {
                'first_name': u_data.get('firstName'),
                'last_name': u_data.get('lastName'),
                'id': u_data.get('id'),
                'email': u_data.get('emailAddress')}
            self.session['linkedin'] = json.dumps(user_data)
            logging.info('linkedin user_data: ' + str(user_data))

            if self.user:
                # new association with linkedin
                user_info = self.user_model.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, 'linkedin', str(user_data['id'])):
                    social_user = models.SocialUser(
                        user=user_info.key,
                        provider='linkedin',
                        uid=str(user_data['id']),
                        extra_data=user_data
                    )
                    social_user.put()

                    message = _('Linkedin association added!')
                    self.add_message(message, 'success')
                else:
                    message = _('This Linkedin account is already in use!')
                    self.add_message(message, 'danger')
                if continue_url:
                    self.redirect(continue_url)
                else:
                    self.redirect_to('edit-profile')
            else:
                # login with Linkedin
                social_user = models.SocialUser.get_by_provider_and_uid('linkedin',
                                                                        str(user_data['id']))
                if social_user:
                    # Social user exists. Need authenticate related site account
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    if self.app.config['log_visit']:
                        try:
                            logVisit = models.LogVisit(
                                user=user.key,
                                uastring=self.request.user_agent,
                                ip=self.request.remote_addr,
                                timestamp=utils.get_date_time()
                            )
                            logVisit.put()
                        except (apiproxy_errors.OverQuotaError, BadValueError):
                            logging.error("Error saving Visit Log in datastore")
                    if continue_url:
                        self.redirect(continue_url)
                    else:
                        self.redirect_to('home')
                else:
                    uid = str(user_data['id'])
                    email = str(user_data.get('email'))
                    self.create_account_from_social_provider(provider_name, uid, email, continue_url, user_data)

                    #end linkedin

        # google, myopenid, yahoo OpenID Providers
        elif provider_name in models.SocialUser.open_id_providers():
            provider_display_name = models.SocialUser.PROVIDERS_INFO[provider_name]['label']
            # get info passed from OpenID Provider
            from google.appengine.api import users

            current_user = users.get_current_user()
            if current_user:
                if current_user.federated_identity():
                    uid = current_user.federated_identity()
                else:
                    uid = current_user.user_id()
                email = current_user.email()
            else:
                message = _('No user authentication information received from %s. '
                            'Please ensure you are logging in from an authorized OpenID Provider (OP).'
                            % provider_display_name)
                self.add_message(message, 'danger')
                return self.redirect_to('login', continue_url=continue_url) if continue_url else self.redirect_to(
                    'login')
            if self.user:
                # add social account to user
                user_info = self.user_model.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, provider_name, uid):
                    social_user = models.SocialUser(
                        user=user_info.key,
                        provider=provider_name,
                        uid=uid
                    )
                    social_user.put()

                    message = _('%s association successfully added.' % provider_display_name)
                    self.add_message(message, 'success')
                else:
                    message = _('This %s account is already in use.' % provider_display_name)
                    self.add_message(message, 'danger')
                if continue_url:
                    self.redirect(continue_url)
                else:
                    self.redirect_to('edit-profile')
            else:
                # login with OpenID Provider
                social_user = models.SocialUser.get_by_provider_and_uid(provider_name, uid)
                if social_user:
                    # Social user found. Authenticate the user
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    if self.app.config['log_visit']:
                        try:
                            logVisit = models.LogVisit(
                                user=user.key,
                                uastring=self.request.user_agent,
                                ip=self.request.remote_addr,
                                timestamp=utils.get_date_time()
                            )
                            logVisit.put()
                        except (apiproxy_errors.OverQuotaError, BadValueError):
                            logging.error("Error saving Visit Log in datastore")
                    if continue_url:
                        self.redirect(continue_url)
                    else:
                        self.redirect_to('home')
                else:
                    self.create_account_from_social_provider(provider_name, uid, email, continue_url)
        else:
            message = _('This authentication method is not yet implemented.')
            self.add_message(message, 'warning')
            self.redirect_to('login', continue_url=continue_url) if continue_url else self.redirect_to('login')

    def create_account_from_social_provider(self, provider_name, uid, email=None, continue_url=None, user_data=None):
        """Social user does not exist yet so create it with the federated identity provided (uid)
        and create prerequisite user and log the user account in
        """
        provider_display_name = models.SocialUser.PROVIDERS_INFO[provider_name]['label']
        if models.SocialUser.check_unique_uid(provider_name, uid):
            # create user
            # Returns a tuple, where first value is BOOL.
            # If True ok, If False no new user is created
            # Assume provider has already verified email address
            # if email is provided so set activated to True
            auth_id = "%s:%s" % (provider_name, uid)
            if email:
                unique_properties = ['email']
                user_info = self.auth.store.user_model.create_user(
                    auth_id, unique_properties, email=email,
                    activated=True
                )
            else:
                user_info = self.auth.store.user_model.create_user(
                    auth_id, activated=True
                )
            if not user_info[0]: #user is a tuple
                message = _('The account %s is already in use.' % provider_display_name)
                self.add_message(message, 'danger')
                return self.redirect_to('register')

            user = user_info[1]

            # create social user and associate with user
            social_user = models.SocialUser(
                user=user.key,
                provider=provider_name,
                uid=uid,
            )
            if user_data:
                social_user.extra_data = user_data
                self.session[provider_name] = json.dumps(user_data) # TODO is this needed?
            social_user.put()
            # authenticate user
            self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
            if self.app.config['log_visit']:
                try:
                    logVisit = models.LogVisit(
                        user=user.key,
                        uastring=self.request.user_agent,
                        ip=self.request.remote_addr,
                        timestamp=utils.get_date_time()
                    )
                    logVisit.put()
                except (apiproxy_errors.OverQuotaError, BadValueError):
                    logging.error("Error saving Visit Log in datastore")

            message = _('Welcome!  You have been registered as a new user '
                        'and logged in through {}.').format(provider_display_name)
            self.add_message(message, 'success')
        else:
            message = _('This %s account is already in use.' % provider_display_name)
            self.add_message(message, 'danger')
        if continue_url:
            self.redirect(continue_url)
        else:
            self.redirect_to('edit-profile')

class DeleteSocialProviderHandler(BaseHandler):
    """
    Delete Social association with an account
    """

    @user_required
    def post(self, provider_name):
        if self.user:
            user_info = self.user_model.get_by_id(long(self.user_id))
            if len(user_info.get_social_providers_info()['used']) > 1 and user_info.password is not None:
                social_user = models.SocialUser.get_by_user_and_provider(user_info.key, provider_name)
                if social_user:
                    social_user.key.delete()
                    message = _('%s successfully disassociated.' % provider_name)
                    self.add_message(message, 'success')
                else:
                    message = _('Social account on %s not found for this user.' % provider_name)
                    self.add_message(message, 'danger')
            else:
                message = ('Social account on %s cannot be deleted for user.'
                           '  Please create a username and password to delete social account.' % provider_name)
                self.add_message(message, 'danger')
        self.redirect_to('edit-profile')

class SendEmailHandler(BaseHandler):
    """
    Core Handler for sending Emails
    Use with TaskQueue
    """

    @taskqueue_method
    def post(self):

        from google.appengine.api import mail, app_identity
        from lib import sendgrid
        from lib.sendgrid import SendGridError, SendGridClientError, SendGridServerError 

        to = self.request.get("to")
        subject = self.request.get("subject")
        body = self.request.get("body")
        sender = self.request.get("sender")

        if sender != '' or not utils.is_email_valid(sender):
            if utils.is_email_valid(self.app.config.get('contact_sender')):
                sender = self.app.config.get('contact_sender')
            else:
                app_id = app_identity.get_application_id()
                sender = "MBoilerplate Mail <no-reply@%s.appspotmail.com>" % (app_id)

        if self.app.config['log_email']:
            try:
                logEmail = models.LogEmail(
                    sender=sender,
                    to=to,
                    subject=subject,
                    body=body,
                    when=utils.get_date_time("datetimeProperty")
                )
                logEmail.put()
            except (apiproxy_errors.OverQuotaError, BadValueError):
                logging.error("Error saving Email Log in datastore")




        #using appengine email 
        try:            
            message = mail.EmailMessage()
            message.sender = sender
            message.to = to
            message.subject = subject
            message.html = body
            message.send()
            logging.info("... sending email to: %s ..." % to)
        except Exception, e:
            logging.error("Error sending email: %s" % e)


        # using sendgrid
        # try:
        #     sg = sendgrid.SendGridClient(self.app.config.get('sendgrid_login'), self.app.config.get('sendgrid_passkey'))
        #     logging.info("sending with sendgrid client: %s" % sg)
        #     message = sendgrid.Mail()
        #     message.add_to(to)
        #     message.set_subject(subject)
        #     message.set_html(body)
        #     message.set_text(body)
        #     message.set_from(sender)
        #     status, msg = sg.send(message)
        # except Exception, e:
        #     logging.error("Error sending email: %s" % e)

class PasswordResetHandler(BaseHandler):
    """
    Password Reset Handler with Captcha
    """

    def get(self):
        if self.user:
            self.auth.unset_session()
        params = {
            'captchahtml': captchaBase(self),
        }
        return self.render_template('materialize/landing/password_reset.html', **params)

    def post(self):
        # check captcha
        response = self.request.POST.get('g-recaptcha-response')
        remote_ip = self.request.remote_addr

        cResponse = captcha.submit(
            response,
            self.app.config.get('captcha_private_key'),
            remote_ip)

        if cResponse.is_valid:
            # captcha was valid... carry on..nothing to see here
            pass
        else:
            _message = _(messages.captcha_error)
            self.add_message(_message, 'danger')
            return self.redirect_to('password-reset')

        #check if we got an email or username
        email_or_username = str(self.request.POST.get('email_or_username')).lower().strip()
        if utils.is_email_valid(email_or_username):
            user = self.user_model.get_by_email(email_or_username)
        else:
            auth_id = "own:%s" % email_or_username
            user = self.user_model.get_by_auth_id(auth_id)

        if user is not None:
            user_id = user.get_id()
            token = self.user_model.create_auth_token(user_id)
            email_url = self.uri_for('taskqueue-send-email')
            reset_url = self.uri_for('password-reset-check', user_id=user_id, token=token, _full=True)
            subject = _(messages.email_passwordassist_subject)

            # load email's template
            template_val = {
                "username": user.name,
                "email": user.email,
                "reset_password_url": reset_url,
                "support_url": self.uri_for("contact", _full=True),
                "faq_url": self.uri_for("faq", _full=True),
                "app_name": self.app.config.get('app_name'),
            }

            body_path = "emails/reset_password.txt"
            body = self.jinja2.render_template(body_path, **template_val)
            taskqueue.add(url=email_url, params={
                'to': user.email,
                'subject': subject,
                'body': body,
                'sender': self.app.config.get('contact_sender'),
            })
            _message = _(messages.password_reset)
            self.add_message(_message, 'success')
        else:
            _message = _(messages.password_reset_invalid_email)
            self.add_message(_message, 'warning')

        return self.redirect_to('login')

class PasswordResetCompleteHandler(BaseHandler):
    """
    Handler to process the link of reset password that received the user
    """

    def get(self, user_id, token):
        verify = self.user_model.get_by_auth_token(int(user_id), token)
        params = {}
        if verify[0] is None:
            message = _(messages.password_reset_invalid_link)
            self.add_message(message, 'warning')
            return self.redirect_to('password-reset')

        else:
            user = self.user_model.get_by_id(long(user_id))
            params = {
                '_username':user.name
            }
            return self.render_template('materialize/landing/password_reset_complete.html', **params)

    def post(self, user_id, token):
        verify = self.user_model.get_by_auth_token(int(user_id), token)
        user = verify[0]
        password = self.form.password.data.strip()
        if user and self.form.validate():
            # Password to SHA512
            password = utils.hashing(password, self.app.config.get('salt'))

            user.password = security.generate_password_hash(password, length=12)
            user.put()
            # Delete token
            self.user_model.delete_auth_token(int(user_id), token)
            # Login User
            self.auth.get_user_by_password(user.auth_ids[0], password)
            self.add_message(_(messages.passwordchange_success), 'success')
            return self.redirect_to('materialize-home')

        else:
            self.add_message(_(messages.passwords_mismatch), 'danger')
            return self.redirect_to('password-reset-check', user_id=user_id, token=token)

    @webapp2.cached_property
    def form(self):
        return forms.PasswordResetCompleteForm(self)




""" REGISTRATION handlers 

    These handlers concern registration in 2 ways: direct, or from referral.

"""
class MaterializeRegisterReferralHandler(BaseHandler):
    """
    Handler to process the link of referrals for a given user_id
    """

    def get(self, user_id):
        if self.user:
            self.redirect_to('materialize-home')
        user = self.user_model.get_by_id(long(user_id))

        if user is not None:
            params = {
                'captchahtml': captchaBase(self),
                '_username': user.name,
                '_email': user.email,
                'is_referral' : True
            }
            return self.render_template('materialize/landing/register.html', **params)
        else:
            return self.redirect_to('landing')

    def post(self, user_id):
        """ Get fields from POST dict """

        # check captcha
        response = self.request.POST.get('g-recaptcha-response')
        remote_ip = self.request.remote_addr

        cResponse = captcha.submit(
            response,
            self.app.config.get('captcha_private_key'),
            remote_ip)

        if cResponse.is_valid:
            # captcha was valid... carry on..nothing to see here
            pass
        else:
            _message = _(messages.captcha_error)
            self.add_message(_message, 'danger')
            return self.get(user_id)

        if not self.form.validate():
            _message = _(messages.saving_error)
            logging.info("Form did not passed.")
            self.add_message(_message, 'danger')
            return self.get(user_id)
        name = self.form.name.data.strip()
        last_name = self.form.last_name.data.strip()
        email = self.form.email.data.lower()
        username = email
        password = self.form.password.data.strip()


        aUser = self.user_model.get_by_email(email)
        if aUser is not None:
            message = _("Sorry, email %s is already in use." % email)
            self.add_message(message, 'danger')
            return self.redirect_to('landing')


        # Password to SHA512
        password = utils.hashing(password, self.app.config.get('salt'))

        # Passing password_raw=password so password will be hashed
        # Returns a tuple, where first value is BOOL.
        # If True ok, If False no new user is created
        unique_properties = ['username', 'email']
        auth_id = "own:%s" % username
        referred_user = self.auth.store.user_model.create_user(
            auth_id, unique_properties, password_raw=password,
            username=username, name=name, last_name=last_name, email=email,
            ip=self.request.remote_addr
        )

        if not referred_user[0]: #user is a tuple
            if "username" in str(referred_user[1]):
                message = _(messages.username_exists).format(username)
            elif "email" in str(referred_user[1]):
                message = _(messages.email_exists).format(email)
            else:
                message = _(messages.user_exists)
            self.add_message(message, 'danger')
            return self.redirect_to('register-referral',user_id=user_id, _full = True)
        else:
            # User registered successfully
            # But if the user registered using the form, the user has to check their email to activate the account ???
            try:
                if not referred_user[1].activated:
                    # send email
                    subject = _(messages.email_activation_subject)
                    confirmation_url = self.uri_for("account-activation-referral",
                                                    ref_user_id=referred_user[1].get_id(),
                                                    token=self.user_model.create_auth_token(referred_user[1].get_id()),
                                                    user_id =  user_id,
                                                    _full=True)
                    if name != '':
                        _username = str(name)
                    else:
                        _username = str(username)
                    # load email's template
                    template_val = {
                        "app_name": self.app.config.get('app_name'),
                        "username": _username,
                        "confirmation_url": confirmation_url,
                        "support_url": self.uri_for("contact", _full=True),
						"faq_url": self.uri_for("faq", _full=True)
                    }
                    body_path = "emails/account_activation.txt"
                    body = self.jinja2.render_template(body_path, **template_val)

                    email_url = self.uri_for('taskqueue-send-email')
                    taskqueue.add(url=email_url, params={
                        'to': str(email),
                        'subject': subject,
                        'body': body,
                    })

                    
                    #unlock rewards status for the user who referred this referred_user
                    already_invited = False;
                    user = self.user_model.get_by_id(long(user_id))
                    for reward in user.rewards:
                        if reward.content == email:
                            already_invited = True;
                            break

                    if not already_invited:
                        reward = models.Rewards(amount = 0,earned = True, category = 'invite',
                            content = email,timestamp = utils.get_date_time(),status = 'invited')                 
                        user.rewards.append(reward)
                        user.put()

                    message = _(messages.register_success)
                    self.add_message(message, 'success')
                    return self.redirect_to('landing')

                # If the user didn't register using registration form ???
                db_user = self.auth.get_user_by_password(referred_user[1].auth_ids[0], password)

                # Check Twitter association in session
                twitter_helper = twitter.TwitterAuth(self)
                twitter_association_data = twitter_helper.get_association_data()
                if twitter_association_data is not None:
                    if models.SocialUser.check_unique(referred_user[1].key, 'twitter', str(twitter_association_data['id'])):
                        social_user = models.SocialUser(
                            user=referred_user[1].key,
                            provider='twitter',
                            uid=str(twitter_association_data['id']),
                            extra_data=twitter_association_data
                        )
                        social_user.put()

                #check Facebook association
                fb_data = json.loads(self.session['facebook'])
                if fb_data is not None:
                    if models.SocialUser.check_unique(referred_user.key, 'facebook', str(fb_data['id'])):
                        social_user = models.SocialUser(
                            user=referred_user.key,
                            provider='facebook',
                            uid=str(fb_data['id']),
                            extra_data=fb_data
                        )
                        social_user.put()

                #check LinkedIn association
                li_data = json.loads(self.session['linkedin'])
                if li_data is not None:
                    if models.SocialUser.check_unique(referred_user.key, 'linkedin', str(li_data['id'])):
                        social_user = models.SocialUser(
                            user=referred_user.key,
                            provider='linkedin',
                            uid=str(li_data['id']),
                            extra_data=li_data
                        )
                        social_user.put()

                message = _(messages.logged).format(username)
                self.add_message(message, 'success')
                return self.redirect_to('materialize-home')
            except (AttributeError, KeyError), e:
                logging.error('Unexpected error creating the user %s: %s' % (username, e ))
                message = _(messages.user_creation_error).format(username)
                self.add_message(message, 'danger')
                return self.redirect_to('register-referral',user_id=user_id, _full = True)

    @webapp2.cached_property
    def form(self):
        f = forms.RegisterForm(self)
        return f

class MaterializeRegisterRequestHandler(BaseHandler):
    """
    Handler for Sign Up Users
    """

    def get(self):
        """ Returns a simple HTML form for create a new user """

        if self.user:
            self.redirect_to('materialize-home')

        params = {
            'captchahtml': captchaBase(self),
        }
        return self.render_template('materialize/landing/register.html', **params)

    def post(self):
        """ Get fields from POST dict """

        # check captcha
        response = self.request.POST.get('g-recaptcha-response')
        remote_ip = self.request.remote_addr

        cResponse = captcha.submit(
            response,
            self.app.config.get('captcha_private_key'),
            remote_ip)

        if cResponse.is_valid:
            # captcha was valid... carry on..nothing to see here
            pass
        else:
            _message = _(messages.captcha_error)
            self.add_message(_message, 'danger')
            return self.redirect_to('register')

        if not self.form.validate():
            logging.info("Form did not passed.")
            _message = _(messages.saving_error)
            self.add_message(_message, 'danger')
            return self.get()
        name = self.form.name.data.strip()
        last_name = self.form.last_name.data.strip()
        email = self.form.email.data.lower()
        username = email
        password = self.form.password.data.strip()


        aUser = self.user_model.get_by_email(email)
        if aUser is not None:
            message = _("Sorry, email %s is already in use." % email)
            self.add_message(message, 'danger')
            return self.redirect_to('landing')

        # Password to SHA512
        password = utils.hashing(password, self.app.config.get('salt'))

        # Passing password_raw=password so password will be hashed
        # Returns a tuple, where first value is BOOL.
        # If True ok, If False no new user is created
        unique_properties = ['username', 'email']
        auth_id = "own:%s" % username
        user = self.auth.store.user_model.create_user(
            auth_id, unique_properties, password_raw=password,
            username=username, name=name, last_name=last_name, email=email,
            ip=self.request.remote_addr
        )

        if not user[0]: #user is a tuple
            if "username" in str(user[1]):
                message = _(messages.username_exists).format(username)
            elif "email" in str(user[1]):
                message = _(messages.email_exists).format(email)
            else:
                message = _(messages.user_exists)
            self.add_message(message, 'danger')
            return self.redirect_to('register')
        else:
            # User registered successfully
            # But if the user registered using the form, the user has to check their email to activate the account ???
            try:
                if not user[1].activated:
                    # send email
                    #subject = _("%s Account Verification" % self.app.config.get('app_name'))
                    subject = _(messages.email_activation_subject)
                    confirmation_url = self.uri_for("account-activation",
                                                    user_id=user[1].get_id(),
                                                    token=self.user_model.create_auth_token(user[1].get_id()),
                                                    _full=True)

                    # load email's template
                    template_val = {
                        "app_name": self.app.config.get('app_name'),
                        "username": name,
                        "confirmation_url": confirmation_url,
                        "support_url": self.uri_for("contact", _full=True),
                        "faq_url": self.uri_for("faq", _full=True)
                    }
                    body_path = "emails/account_activation.txt"
                    body = self.jinja2.render_template(body_path, **template_val)

                    email_url = self.uri_for('taskqueue-send-email')
                    taskqueue.add(url=email_url, params={
                        'to': str(email),
                        'subject': subject,
                        'body': body,
                    })

                    message = _(messages.register_success)
                    self.add_message(message, 'success')
                    return self.redirect_to('landing')

                # If the user didn't register using registration form ???
                db_user = self.auth.get_user_by_password(user[1].auth_ids[0], password)

                message = _(messages.logged).format(username)
                self.add_message(message, 'success')
                return self.redirect_to('landing')
            except (AttributeError, KeyError), e:
                logging.error('Unexpected error creating the user %s: %s' % (username, e ))
                message = _(messages.user_creation_error).format(username)
                self.add_message(message, 'danger')
                return self.redirect_to('landing')

    @webapp2.cached_property
    def form(self):
        f = forms.RegisterForm(self)
        return f

class MaterializeLoginRequestHandler(BaseHandler):
    """
    Handler for authentication
    """

    def get(self):
        """ Returns a simple HTML form for login """

        if self.user:
            self.redirect_to('landing')

        params = {
            'captchahtml': captchaBase(self),
        }
        continue_url = self.request.get('continue').encode('ascii', 'ignore')
        params['continue_url'] = continue_url
        return self.render_template('materialize/landing/login.html', **params)

    def post(self):
        """
        email: Get the email from POST dict
        password: Get the password from POST dict
        """

        if not self.form.validate():
            _message = _(messages.post_error)
            self.add_message(_message, 'danger')
            return self.get()
        email = self.form.email.data.lower()
        continue_url = self.request.get('continue').encode('ascii', 'ignore')

        try:
            if utils.is_email_valid(email):
                user = self.user_model.get_by_email(email)
                if user:
                    auth_id = user.auth_ids[0]
                else:
                    raise InvalidAuthIdError
            else:
                auth_id = "own:%s" % email
                user = self.user_model.get_by_auth_id(auth_id)
            
            password = self.form.password.data.strip()
            remember_me = True if str(self.request.POST.get('remember_me')) == 'on' else False

            # Password to SHA512
            password = utils.hashing(password, self.app.config.get('salt'))

            # Try to login user with password
            # Raises InvalidAuthIdError if user is not found
            # Raises InvalidPasswordError if provided password
            # doesn't match with specified user
            self.auth.get_user_by_password(
                auth_id, password, remember=remember_me)

            # if user account is not activated, logout and redirect to home
            if (user.activated == False):
                # logout
                self.auth.unset_session()

                # redirect to home with error message
                resend_email_uri = self.uri_for('resend-account-activation', user_id=user.get_id(),
                                                token=self.user_model.create_resend_token(user.get_id()))
                message = _(messages.inactive_account) + ' ' + resend_email_uri
                self.add_message(message, 'danger')
                return self.redirect_to('login')
            else:
                try:
                    user.last_login = utils.get_date_time()
                    user.put()
                except (apiproxy_errors.OverQuotaError, BadValueError):
                    logging.error("Error saving Last Login in datastore")
            

            if self.app.config['log_visit']:
                try:
                    logVisit = models.LogVisit(
                        user=user.key,
                        uastring=self.request.user_agent,
                        ip=self.request.remote_addr,
                        timestamp=utils.get_date_time()
                    )
                    logVisit.put()
                except (apiproxy_errors.OverQuotaError, BadValueError):
                    logging.error("Error saving Visit Log in datastore")
            if continue_url:
                self.redirect(continue_url)
            else:
                message = _('Welcome back, %s! ' % user.name)
                self.add_message(message, 'success')
                self.redirect_to('landing')
        except (InvalidAuthIdError, InvalidPasswordError), e:
            # Returns error message to self.response.write in
            # the BaseHandler.dispatcher
            message = _(messages.user_pass_mismatch)
            self.add_message(message, 'danger')
            self.redirect_to('login', continue_url=continue_url) if continue_url else self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        return forms.LoginForm(self)

class MaterializeLogoutRequestHandler(BaseHandler):
    """
    Destroy user session and redirect to login
    """

    def get(self):
        if self.user:
            message = _(messages.logout)
            self.add_message(message, 'info')

        self.auth.unset_session()
        # User is logged out, let's try redirecting to login page
        try:
            self.redirect_to('landing')
        except (AttributeError, KeyError), e:
            logging.error("Error logging out: %s" % e)
            message = _(messages.logout_error)
            self.add_message(message, 'danger')
            return self.redirect_to('landing')

class MaterializeAccountActivationHandler(BaseHandler):
    """
    Handler for account activation
    """

    def get(self, user_id, token):
        try:
            if not self.user_model.validate_auth_token(user_id, token):
                message = _(messages.used_activation_link)
                self.add_message(message, 'danger')
                return self.redirect_to('login')

            user = self.user_model.get_by_id(long(user_id))
            # activate the user's account
            user.activated = True
            user.last_login = utils.get_date_time()
            
            # create unique url for sharing & referrals purposes
            long_url = self.uri_for("register-referral",user_id=user.get_id(),_full=True)
            logging.info("Long URL: %s" % long_url)
            
            #The goo.gl way:
            # post_url = 'https://www.googleapis.com/urlshortener/v1/url'            
            # payload = {'longUrl': long_url}
            # headers = {'content-type': 'application/json'}
            # r = requests.post(post_url, data=json.dumps(payload), headers=headers)
            # j = json.loads(r.text)
            # logging.info("Google response: %s" % j)
            # short_url = j['id']

            #The bit.ly way:
            api = bitly.Api(login=self.app.config.get('bitly_login'), apikey=self.app.config.get('bitly_apikey'))
            short_url=api.shorten(long_url)
            logging.info("Bitly response: %s" % short_url)

            user.link_referral = short_url
            reward = models.Rewards(amount = 100,earned = True, category = 'configuration',
                content = 'Activation',timestamp = utils.get_date_time(),status = 'completed')                 
            user.rewards.append(reward)

            #Role init
            user.role = 'Admin'

            #Datastore allocation
            user.put()

            # Login User
            self.auth.get_user_by_token(int(user_id), token)

            # Delete token
            self.user_model.delete_auth_token(user_id, token)

            # Slack Incoming WebHooks
            from google.appengine.api import urlfetch            
            urlfetch.fetch(self.app.config.get('slack_webhook_url'), payload='{"channel": "#general", "username": "webhookbot", "text": "just got a new user ! Go surprise him at '+user.email+'", "icon_emoji": ":bowtie:"}', method='POST')

            message = _(messages.activation_success).format(
                user.email)
            self.add_message(message, 'success')
            self.redirect_to('landing')

        except (AttributeError, KeyError, InvalidAuthIdError, NameError), e:
            logging.error("Error activating an account: %s" % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('landing')

class MaterializeAccountActivationReferralHandler(BaseHandler):
    """
    Handler for account activation
    """

    def get(self, ref_user_id, token, user_id):
        try:
            if not self.user_model.validate_auth_token(ref_user_id, token):
                message = _(messages.used_activation_link)
                self.add_message(message, 'danger')
                return self.redirect_to('login')


            user = self.user_model.get_by_id(long(user_id))
            referred_user = self.user_model.get_by_id(long(ref_user_id))
            
            # activate the user's account            
            referred_user.activated = True
            referred_user.last_login = utils.get_date_time()
            
            # create unique url for sharing & referrals purposes
            long_url = self.uri_for("register-referral",user_id=referred_user.get_id(),_full=True)
            logging.info("Long URL: %s" % long_url)
            
            #The goo.gl way:
            # post_url = 'https://www.googleapis.com/urlshortener/v1/url'            
            # payload = {'longUrl': long_url}
            # headers = {'content-type': 'application/json'}
            # r = requests.post(post_url, data=json.dumps(payload), headers=headers)
            # j = json.loads(r.text)
            # logging.info("Google response: %s" % j)
            # short_url = j['id']

            #The bit.ly way:
            api = bitly.Api(login=self.app.config.get('bitly_login'), apikey=self.app.config.get('bitly_apikey'))
            short_url=api.shorten(long_url)
            logging.info("Bitly response: %s" % short_url)


            referred_user.link_referral = short_url
            reward = models.Rewards(amount = 100,earned = True, category = 'configuration',
                content = 'Activation',timestamp = utils.get_date_time(),status = 'completed')                 
            referred_user.rewards.append(reward)
            reward = models.Rewards(amount = 20,earned = True, category = 'invite',
                content = 'Invitee by: ' + user.email,timestamp = utils.get_date_time(),status = 'completed')                 
            referred_user.rewards.append(reward)


            #Role init
            referred_user.role = 'Admin'

            #Datastore allocation
            referred_user.put()
            
            # assign the referral reward
            for reward in user.rewards:
                if reward.content == referred_user.email:
                    reward.amount = 50;
                    reward.status = 'joined';
                    user.put()
                    break

            # Login User
            self.auth.get_user_by_token(int(ref_user_id), token)

            # Delete token
            self.user_model.delete_auth_token(ref_user_id, token)

            # Slack Incoming WebHooks
            from google.appengine.api import urlfetch
            urlfetch.fetch(self.app.config.get('slack_webhook_url'), payload='{"channel": "#general", "username": "webhookbot", "text": "Just got a new referred user ! Go surprise him at '+referred_user.email+' and remember to thank '+ user.email +'", "icon_emoji": ":bowtie:"}', method='POST')


            message = _(messages.activation_success).format(
                referred_user.email)
            self.add_message(message, 'success')
            self.redirect_to('landing')

        except (AttributeError, KeyError, InvalidAuthIdError, NameError), e:
            logging.error("Error activating an account: %s" % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('login')

class ResendActivationEmailHandler(BaseHandler):
    """
    Handler to resend activation email
    """

    def get(self, user_id, token):
        try:
            if not self.user_model.validate_resend_token(user_id, token):
                message = _(messages.used_activation_link)
                self.add_message(message, 'danger')
                return self.redirect_to('login')

            user = self.user_model.get_by_id(long(user_id))
            email = user.email

            if (user.activated == False):
                # send email
                subject = _(messages.email_activation_subject)
                confirmation_url = self.uri_for("account-activation",
                                                user_id=user.get_id(),
                                                token=self.user_model.create_auth_token(user.get_id()),
                                                _full=True)
                # load email's template
                template_val = {
                    "app_name": self.app.config.get('app_name'),
                    "username": user.name,
                    "confirmation_url": confirmation_url,
                    "support_url": self.uri_for("contact", _full=True),
					"faq_url": self.uri_for("faq", _full=True)
                }
                body_path = "emails/account_activation.txt"
                body = self.jinja2.render_template(body_path, **template_val)

                email_url = self.uri_for('taskqueue-send-email')
                taskqueue.add(url=email_url, params={
                    'to': str(email),
                    'subject': subject,
                    'body': body,
                })

                self.user_model.delete_resend_token(user_id, token)

                message = _(messages.resend_success).format(email)
                self.add_message(message, 'success')
                return self.redirect_to('login')
            else:
                message = _(messages.activation_success)
                self.add_message(message, 'warning')
                return self.redirect_to('materialize-home')

        except (KeyError, AttributeError), e:
            logging.error("Error resending activation email: %s" % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('login')




""" MATERIALIZE handlers 

    These handlers are the core of the Platform, they give life to main user materialized screens

"""
def disclaim(_self, **kwargs):
    """
        This method is used as a validator previous to loading a get handler for most of user's screens.
        It can either redirect user to login, edit cfe data and edit home data, or
        return required params, user_info and user_home values.
    """
    _params = {}
    user_info = _self.user_model.get_by_id(long(_self.user_id))        
    
    #0: FOR PERSONALIZATION MEANS WE TAKE CARE OF BEST DATA TO ADDRESS USER
    _params['email'] = user_info.email
    _params['last_name'] = user_info.last_name
    _params['last_name_i'] = user_info.last_name[0] + "." if len(user_info.last_name) >= 1 else ""
    _params['name'] = user_info.name
    _params['name_i'] = user_info.name[0].upper()
    _params['role'] = 'Administrator' if user_info.role == 'Admin' else 'Member'
    _params['phone'] = user_info.phone if user_info.phone != None else ""
    _params['gender'] = user_info.gender if user_info.gender != None else ""
    _params['birth'] = user_info.birth.strftime("%Y-%m-%d") if user_info.birth != None else ""
    _params['has_picture'] = True if user_info.picture is not None else False
    if not _params['has_picture']:
        _params['disclaim'] = True
    _params['link_referral'] = user_info.link_referral
    _params['date'] = date.today().strftime("%Y-%m-%d")

    return _params, user_info


# LANDING
class MaterializeLandingRequestHandler(BaseHandler):
    """
    Handler to show the landing page
    """

    def get(self):
        """ Returns a simple HTML form for landing """
        params = {}
        if not self.user:
            params['captchahtml'] = captchaBase(self)
            message = _(messages.welcome_message)

            self.add_message(message, 'success')
            return self.render_template('materialize/landing/base.html', **params)
        else:
            params, user_info = disclaim(self)            
            return self.render_template('materialize/landing/base.html', **params)

class MaterializeLandingBlogRequestHandler(BaseHandler):
    """
        Handler for materialized privacy policy
    """
    def get(self):
        """ returns simple html for a get request """
        if self.user_id:
            params, user_info = disclaim(self)
        else:
            params = {}        
        params['captchahtml'] = captchaBase(self)
        posts = models.BlogPost.query()
        params['total'] = posts.count()
        params['posts'] = []
        for post in posts:
            categories = ""
            for category in post.category:
                categories += str(category) + ", "
            params['posts'].append((post.key.id(), post.updated.strftime("%Y-%m-%d"), post.title, post.subtitle, post.blob_key, post.author, post.brief, categories[0:-2]))
        return self.render_template('materialize/landing/blog.html', **params)

class MaterializeLandingBlogPostRequestHandler(BaseHandler):
    """
        Handler for materialized privacy policy
    """
    def get(self, post_id):
        """ returns simple html for a get request """
        if self.user_id:
            params, user_info = disclaim(self)
        else:
            params = {} 
        params['captchahtml'] = captchaBase(self)
        blog = models.BlogPost.get_by_id(long(post_id))
        if blog is not None:
            params['title'] = blog.title
            params['subtitle'] = blog.subtitle
            params['blob_key'] = blog.blob_key
            params['author'] = blog.author
            params['content'] = blog.content
            return self.render_template('materialize/landing/blogpost.html', **params)
        else:
            return self.error(404)

class MaterializeLandingFaqRequestHandler(BaseHandler):
    """
        Handler for materialized frequented asked questions
    """
    def get(self):
        """ returns simple html for a get request """
        if self.user_id:
            params, user_info = disclaim(self)
        else:
            params = {} 
        params['captchahtml'] = captchaBase(self)
        return self.render_template('materialize/landing/faq.html', **params)

class MaterializeLandingTouRequestHandler(BaseHandler):
    """
        Handler for materialized terms of use
    """
    def get(self):
        """ returns simple html for a get request """
        if self.user_id:
            params, user_info = disclaim(self)
        else:
            params = {} 
        params['captchahtml'] = captchaBase(self)
        return self.render_template('materialize/landing/tou.html', **params)

class MaterializeLandingPrivacyRequestHandler(BaseHandler):
    """
        Handler for materialized privacy policy
    """
    def get(self):
        """ returns simple html for a get request """
        if self.user_id:
            params, user_info = disclaim(self)
        else:
            params = {} 
        params['captchahtml'] = captchaBase(self)
        return self.render_template('materialize/landing/privacy.html', **params)

class MaterializeLandingLicenseRequestHandler(BaseHandler):
    """
        Handler for materialized privacy policy
    """
    def get(self):
        """ returns simple html for a get request """
        if self.user_id:
            params, user_info = disclaim(self)
        else:
            params = {} 
        params['captchahtml'] = captchaBase(self)
        return self.render_template('materialize/landing/license.html', **params)

class MaterializeLandingContactRequestHandler(BaseHandler):
    """
        Handler for materialized contact us
    """
    def get(self):
        """ returns simple html for a get request """
        if self.user_id:
            params, user_info = disclaim(self)
        else:
            params = {} 
        params['captchahtml'] = captchaBase(self)
        if self.user:
            user_info = self.user_model.get_by_id(long(self.user_id))
            if user_info.name or user_info.last_name:
                self.form.name.data = user_info.name + " " + user_info.last_name
            if user_info.email:
                self.form.email.data = user_info.email
        params['exception'] = self.request.get('exception')

        params['t'] = str(self.request.get('t')) if len(self.request.get('t')) > 1 else 'no'

        return self.render_template('materialize/landing/contact.html', **params)

    def post(self):
        """ validate contact form """
        if not self.form.validate():
            _message = _(messages.post_error)
            self.add_message(_message, 'danger')
            return self.get()

        import bp_includes.lib.i18n as i18n
        from bp_includes.external import httpagentparser

        remote_ip = self.request.remote_addr
        city = i18n.get_city_code(self.request)
        region = i18n.get_region_code(self.request)
        country = i18n.get_country_code(self.request)
        coordinates = i18n.get_city_lat_long(self.request)
        user_agent = self.request.user_agent
        exception = self.request.POST.get('exception')
        name = self.form.name.data.strip()
        email = self.form.email.data.lower()
        message = self.form.message.data.strip()
        template_val = {
            "name": name,
            "email": email,
            "ip": remote_ip,
            "city": city,
            "region": region,
            "country": country,
            "coordinates": coordinates,
            "message": message
        }
        try:
            # parsing user_agent and getting which os key to use
            # windows uses 'os' while other os use 'flavor'
            ua = httpagentparser.detect(user_agent)
            _os = ua.has_key('flavor') and 'flavor' or 'os'

            operating_system = str(ua[_os]['name']) if "name" in ua[_os] else "-"
            if 'version' in ua[_os]:
                operating_system += ' ' + str(ua[_os]['version'])
            if 'dist' in ua:
                operating_system += ' ' + str(ua['dist'])

            browser = str(ua['browser']['name']) if 'browser' in ua else "-"
            browser_version = str(ua['browser']['version']) if 'browser' in ua else "-"

            template_val = {
                "name": name,
                "email": email,
                "ip": remote_ip,
                "city": city,
                "region": region,
                "country": country,
                "coordinates": coordinates,

                "browser": browser,
                "browser_version": browser_version,
                "operating_system": operating_system,
                "message": message
            }
        except Exception as e:
            logging.error("error getting user agent info: %s" % e)

        try:
            subject = _("Alguien ha enviado un mensaje")
            # exceptions for error pages that redirect to contact
            if exception != "":
                subject = "{} (Exception error: {})".format(subject, exception)

            body_path = "emails/contact.txt"
            body = self.jinja2.render_template(body_path, **template_val)

            email_url = self.uri_for('taskqueue-send-email')
            taskqueue.add(url=email_url, params={
                'to': self.app.config.get('contact_recipient'),
                'subject': subject,
                'body': body,
                'sender': self.app.config.get('contact_sender'),
            })

            message = _(messages.contact_success)
            self.add_message(message, 'success')
            return self.redirect_to('contact')

        except (AttributeError, KeyError), e:
            logging.error('Error sending contact form: %s' % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('contact')

    @webapp2.cached_property
    def form(self):
        return forms.ContactForm(self)


# USER
class MaterializeHomeRequestHandler(BaseHandler):
    """
    Handler for materialized home
    """
    @user_required
    def get(self):
        """ Returns a simple HTML form for materialize home """
        ####-------------------- R E D I R E C T I O N S --------------------####
        if not self.user:
            return self.redirect_to('login')
        ####------------------------------------------------------------------####

        ####-------------------- P R E P A R A T I O N S --------------------####
        params, user_info = disclaim(self)
        ####------------------------------------------------------------------####
        
        return self.render_template('materialize/users/sections/home.html', **params)

class MaterializeReferralsRequestHandler(BaseHandler):
    """
        Handler for materialized referrals
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info = disclaim(self)
        params['link_referral'] = user_info.link_referral
        return self.render_template('materialize/users/sections/referrals.html', **params)

    def post(self):
        """ Get fields from POST dict """
        user_info = self.user_model.get_by_id(long(self.user_id))
        message = ''

        if not self.form.validate():
            message += messages.saving_error
            self.add_message(message, 'danger')
            return self.get()

        _emails = self.form.emails.data.replace('"','').replace('[','').replace(']','')
        logging.info("Referrals' email addresses: %s" % _emails)

        try:
            # send email
            subject = _(messages.email_referral_subject)
            if user_info.name != '':
                _username = user_info.name
            else:
                _username = user_info.username
             # load email's template
            template_val = {
                "app_name": self.app.config.get('app_name'),
                "user_email": user_info.email,
                "user_name": _username,
                "link_referral" : user_info.link_referral,
                "support_url": self.uri_for("contact", _full=True),
                "faq_url": self.uri_for("faq", _full=True)
            }
            body_path = "emails/referrals.txt"
            body = self.jinja2.render_template(body_path, **template_val)

            email_url = self.uri_for('taskqueue-send-email')
            _email = _emails.split(",")
            _email = list(set(_email)) #removing duplicates

            for _email_ in _email:

                aUser = self.user_model.get_by_email(_email_)
                if aUser is not None:
                    reward = models.Rewards(amount = 0,earned = True, category = 'invite',content = _email_,
                                            timestamp = utils.get_date_time(),status = 'inelegible')                 
                    edited_userinfo = False
                    for rewards in user_info.rewards:
                        if 'invite' in rewards.category and rewards.content == reward.content:
                            user_info.rewards[user_info.rewards.index(rewards)] = reward
                            edited_userinfo = True
                    if not edited_userinfo:
                        user_info.rewards.append(reward)
                else:
                    taskqueue.add(url=email_url, params={
                        'to': str(_email_),
                        'subject': subject,
                        'body': body,
                    })
                    logging.info('Sent referral invitation to %s' % str(_email_))
                    reward = models.Rewards(amount = 0,earned = True, category = 'invite',content = _email_,
                                            timestamp = utils.get_date_time(),status = 'invited')                 
                    edited_userinfo = False
                    for rewards in user_info.rewards:
                        if 'invite' in rewards.category and rewards.content == reward.content:
                            user_info.rewards[user_info.rewards.index(rewards)] = reward
                            edited_userinfo = True
                    if not edited_userinfo:
                        user_info.rewards.append(reward)
                    
            user_info.put()

            message += " " + _(messages.invite_success)
            self.add_message(message, 'success')
            return self.get()
           
        except (KeyError, AttributeError), e:
            logging.error("Error resending invitation email: %s" % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('home')

          
    @webapp2.cached_property
    def form(self):
        f = forms.ReferralsForm(self)
        return f


class MaterializePolymerRequestHandler(BaseHandler):
    """
    Handler for materialized polymer
    """
    @user_required
    def get(self):
        """ Returns a simple HTML form for materialize home """
        ####-------------------- R E D I R E C T I O N S --------------------####
        if not self.user:
            return self.redirect_to('login')
        ####------------------------------------------------------------------####

        ####-------------------- P R E P A R A T I O N S --------------------####
        params, user_info = disclaim(self)
        ####------------------------------------------------------------------####
        
        return self.render_template('materialize/users/sections/polymer.html', **params)

class MaterializeCartoDBRequestHandler(BaseHandler):
    """
    Handler for materialized home
    """
    @user_required
    def get(self):
        """ Returns a simple HTML form for materialize home """
        ####-------------------- R E D I R E C T I O N S --------------------####
        if not self.user:
            return self.redirect_to('login')
        ####------------------------------------------------------------------####

        ####-------------------- P R E P A R A T I O N S --------------------####
        params, user_info = disclaim(self)
        ####------------------------------------------------------------------####
        
        return self.render_template('materialize/users/sections/cartodb.html', **params)


class MaterializeSettingsProfileRequestHandler(BaseHandler):
    """
        Handler for materialized settings profile
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info = disclaim(self)
        return self.render_template('materialize/users/settings/profile.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            message = _(messages.saving_error)
            self.add_message(message, 'danger')
            return self.get()
        name = self.request.get('name')
        last_name = self.request.get('last_name')
        gender = self.request.get('gender')
        phone = self.request.get('phone')
        birth = self.request.get('birth')
        picture = self.request.get('picture') if len(self.request.get('picture'))>1 else None

        try:
            user_info = self.user_model.get_by_id(long(self.user_id))

            try:
                message = ''
                user_info.name = name
                user_info.last_name = last_name
                if (len(birth) > 9):
                    user_info.birth = date(int(birth[:4]), int(birth[5:7]), int(birth[8:]))
                if 'male' in gender:
                    user_info.gender = gender
                user_info.phone = phone
                if picture is not None:
                    user_info.picture = images.resize(picture, width=180, height=180, crop_to_fit=True, quality=100)
                user_info.put()
                message += " " + _(messages.saving_success)
                self.add_message(message, 'success')
                return self.get()

            except (AttributeError, KeyError, ValueError), e:
                logging.error('Error updating profile: %s ' % e)
                message = _(messages.saving_error)
                self.add_message(message, 'danger')
                return self.get()

        except (AttributeError, TypeError), e:
            login_error_message = _(messages.expired_session)
            logging.error('Error updating profile: %s' % e)
            self.add_message(login_error_message, 'danger')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        f = forms.SettingsProfileForm(self)
        return f

class MaterializeSettingsAddressRequestHandler(BaseHandler):
    """
        Handler for materialized settings home
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info = disclaim(self)
        params['zipcode'] = ''
        params['neighborhood'] = False
        params['latlng'] = 'null'
            
        return self.render_template('materialize/users/settings/address.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            message = _(messages.saving_error)
            message += "Tip: Asegura que el marcador en el mapa se encuentre en tu zona."
            self.add_message(message, 'danger')
            return self.get()
        zipcode = int(self.form.zipcode.data)
        ageb = self.form.ageb.data
        latlng = self.form.latlng.data
        neighborhood = self.form.neighborhood.data
        municipality = self.form.municipality.data
        state = self.form.state.data
        region = self.form.region.data

        try:
            user_info = self.user_model.get_by_id(long(self.user_id))
            try:
                
                user_info.address.zipcode = int(zipcode)
                user_info.address.ageb = ageb
                user_info.address.neighborhood = neighborhood
                user_info.address.municipality = municipality
                user_info.address.state = state
                user_info.address.region = region
                user_info.address.latlng = ndb.GeoPt(latlng)
                user_info.put()

                message = ''                
                message += " " + _(messages.saving_success)
                self.add_message(message, 'success')
                return self.get()

            except (AttributeError, KeyError, ValueError), e:
                logging.error('Error updating address: ' + e)
                message = _(messages.saving_error)
                self.add_message(message, 'danger')
                return self.get()

        except (AttributeError, TypeError), e:
            login_error_message = _(messages.expired_session)
            self.add_message(login_error_message, 'danger')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        f = forms.AddressForm(self)
        return f

class MaterializeSettingsReferralsRequestHandler(BaseHandler):
    """
        Handler for materialized settings referrals
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info = disclaim(self)
        params['referrals'] = []
        rewards = user_info.rewards
        rewards.reverse
        unique_emails = []
        page = 1
        if self.request.get('p') != '':
            page = 1 + int(self.request.get('p'))
        offset = (page - 1)*51
        last = page*51
        if last > len(rewards):
            last = len(rewards)
        for i in range(offset, last):
            if 'invite' in rewards[i].category and rewards[i].content != '' and 'Invitado Invictus' not in rewards[i].content and rewards[i].content not in unique_emails:
                params['referrals'].append(rewards[i])
                unique_emails.append(rewards[i].content)
                if rewards[i].status == 'invited':
                    aUser = self.user_model.get_by_email(rewards[i].content)
                    if aUser is not None:
                        params['referrals'][params['referrals'].index(rewards[i])].status = 'inelegible'

        params['page'] = page
        params['last_page'] = int(len(rewards)/50)
        params['total'] = len(params['referrals'])
        params['grand_total'] = int(len(rewards))
        params['properties'] = ['timestamp','content','status']

        return self.render_template('materialize/users/settings/referrals.html', **params)

    def post(self):
        """ Get fields from POST dict """
        user_info = self.user_model.get_by_id(long(self.user_id))
        message = ''

        if not self.form.validate():
            message += messages.saving_error
            self.add_message(message, 'error')
            return self.get()

        _emails = self.form.emails.data.replace('"','').replace('[','').replace(']','')
        logging.info("Referrals' email addresses: %s" % _emails)

        try:
            # send email
            subject = _(messages.email_referral_subject)
            if user_info.name != '':
                _username = user_info.name
            else:
                _username = user_info.username
             # load email's template
            template_val = {
                "app_name": self.app.config.get('app_name'),
                "user_email": user_info.email,
                "user_name": _username,
                "link_referral" : user_info.link_referral,
                "support_url": self.uri_for("contact", _full=True),
                "faq_url": self.uri_for("faq", _full=True)
            }
            body_path = "emails/referrals.txt"
            body = self.jinja2.render_template(body_path, **template_val)

            email_url = self.uri_for('taskqueue-send-email')
            _email = _emails.split(",")

            for _email_ in _email:
                taskqueue.add(url=email_url, params={
                    'to': str(_email_),
                    'subject': subject,
                    'body': body,
                })
                reward = models.Rewards(amount = 0,earned = True, category = 'invite',content = _email_,
                                        timestamp = utils.get_date_time(),status = 'invited')    
                
                edited_userinfo = False
                for rewards in user_info.rewards:
                    if 'invite' in rewards.category and rewards.content == reward.content:
                        user_info.rewards[user_info.rewards.index(rewards)] = reward
                        edited_userinfo = True
                if not edited_userinfo:
                    user_info.rewards.append(reward)

                user_info.put()

            message += " " + _(messages.invite_success)
            self.add_message(message, 'success')
            return self.get()
           
        except (KeyError, AttributeError), e:
            logging.error("Error resending invitation email: %s" % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('home')

          
    @webapp2.cached_property
    def form(self):
        f = forms.ReferralsForm(self)
        return f

class MaterializeSettingsAccountRequestHandler(BaseHandler):
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info = disclaim(self)
        params['captchahtml'] = captchaBase(self)
        for auth_id in user_info.auth_ids:
            logging.info("auth id: %s" % auth_id)
        return self.render_template('materialize/users/settings/account.html', **params)

class MaterializeSettingsEmailRequestHandler(BaseHandler):
    """
        Handler for materialized settings email
    """
    @user_required
    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            _message = _(messages.saving_error)
            self.add_message(_message, 'danger')
            return self.redirect_to('materialize-settings-account')
        new_email = self.form.new_email.data.strip()
        password = self.form.password.data.strip()

        try:
            user_info = self.user_model.get_by_id(long(self.user_id))
            auth_id = "own:%s" % user_info.username
            # Password to SHA512
            password = utils.hashing(password, self.app.config.get('salt'))

            try:
                # authenticate user by its password
                user = self.user_model.get_by_auth_password(auth_id, password)

                # if the user change his/her email address
                if new_email != user.email:

                    # check whether the new email has been used by another user
                    aUser = self.user_model.get_by_email(new_email)
                    if aUser is not None:
                        message = _("Sorry, email %s is already in use." % new_email)
                        self.add_message(message, 'danger')
                        return self.redirect_to('materialize-settings-account')

                    # send email
                    subject = _(messages.email_emailchanged_subject)
                    user_token = self.user_model.create_auth_token(self.user_id)
                    confirmation_url = self.uri_for("materialize-email-changed-check",
                                                    user_id=user_info.get_id(),
                                                    encoded_email=utils.encode(new_email),
                                                    token=user_token,
                                                    _full=True)
                    if user.name != '':
                        _username = user.name
                    else:
                        _username = user.email
                    # load email's template
                    template_val = {
                        "app_name": self.app.config.get('app_name'),
                        "username": _username,
                        "new_email": new_email,
                        "confirmation_url": confirmation_url,
                        "support_url": self.uri_for("contact", _full=True),
                        "faq_url": self.uri_for("faq", _full=True)
                    }

                    old_body_path = "emails/email_changed_notification_old.txt"
                    old_body = self.jinja2.render_template(old_body_path, **template_val)

                    new_body_path = "emails/email_changed_notification_new.txt"
                    new_body = self.jinja2.render_template(new_body_path, **template_val)

                    email_url = self.uri_for('taskqueue-send-email')
                    taskqueue.add(url=email_url, params={
                        'to': user.email,
                        'subject': subject,
                        'body': old_body,
                    })
                    taskqueue.add(url=email_url, params={
                        'to': new_email,
                        'subject': subject,
                        'body': new_body,
                    })

                    # display successful message
                    msg = _(messages.emailchanged_success)
                    self.add_message(msg, 'success')
                    return self.redirect_to('materialize-settings-account')

                else:
                    self.add_message(_(messages.emailchanged_error), "warning")
                    return self.redirect_to('materialize-settings-account')


            except (InvalidAuthIdError, InvalidPasswordError), e:
                # Returns error message to self.response.write in
                # the BaseHandler.dispatcher
                message = _(messages.password_wrong)
                self.add_message(message, 'danger')
                return self.redirect_to('materialize-settings-account')

        except (AttributeError, TypeError), e:
            login_error_message = _(messages.expired_session)
            self.add_message(login_error_message, 'danger')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        return forms.EditEmailForm(self)

class MaterializeEmailChangedCompleteHandler(BaseHandler):
    """
    Handler for completed email change
    Will be called when the user click confirmation link from email
    """

    @user_required
    def get(self, user_id, encoded_email, token):
        verify = self.user_model.get_by_auth_token(int(user_id), token)
        email = utils.decode(encoded_email)
        if verify[0] is None:
            message = _(messages.used_activation_link)
            self.add_message(message, 'warning')
            self.redirect_to('materialize-home')

        else:
            # save new email
            user = verify[0]
            x = ndb.Key("Unique", "User.username:%s" % user.email).get()
            y = ndb.Key("Unique", "User.auth_id:own:%s" % user.email).get()
            z = ndb.Key("Unique", "User.email:%s" % user.email).get()
            ndb.Key("Unique", "User.username:%s" % user.email).delete_async()
            ndb.Key("Unique", "User.auth_id:own:%s" % user.email).delete_async()
            ndb.Key("Unique", "User.email:%s" % user.email).delete_async()

            for i in range(0,len(user.auth_ids)):
                if user.auth_ids[i] == "own:%s" % user.email:
                    user.auth_ids[i] = "own:%s" % email
                    break
            user.email = email
            user.username = email
            user.put()

            x.key = ndb.Key("Unique", "User.username:%s" % user.email)
            y.key = ndb.Key("Unique", "User.auth_id:own:%s" % user.email)
            z.key = ndb.Key("Unique", "User.email:%s" % user.email)
            x.put()
            y.put()
            z.put()


            # delete token
            self.user_model.delete_auth_token(int(user_id), token)
            # add successful message and redirect
            message = _(messages.emailchanged_confirm)
            self.add_message(message, 'success')
            self.redirect_to('materialize-home')

class MaterializeSettingsPasswordRequestHandler(BaseHandler):
    """
        Handler for materialized settings password
    """
    @user_required
    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            self.add_message(_(messages.passwords_mismatch), 'danger')
            return self.redirect_to('materialize-settings-account')

        current_password = self.form.current_password.data.strip()
        password = self.form.password.data.strip()

        try:
            user_info = self.user_model.get_by_id(long(self.user_id))
            auth_id = "own:%s" % user_info.username

            # Password to SHA512
            current_password = utils.hashing(current_password, self.app.config.get('salt'))
            try:
                user = self.user_model.get_by_auth_password(auth_id, current_password)
                # Password to SHA512
                password = utils.hashing(password, self.app.config.get('salt'))
                user.password = security.generate_password_hash(password, length=12)
                user.put()

                # send email
                subject = messages.email_passwordchanged_subject
                if user.name != '':
                    _username = user.name
                else:
                    _username = user.email
                # load email's template
                template_val = {
                    "app_name": self.app.config.get('app_name'),
                    "username": _username,
                    "email": user.email,
                    "reset_password_url": self.uri_for("password-reset", _full=True),
                    "support_url": self.uri_for("contact", _full=True),
                    "faq_url": self.uri_for("faq", _full=True)
                }
                email_body_path = "emails/password_changed.txt"
                email_body = self.jinja2.render_template(email_body_path, **template_val)
                email_url = self.uri_for('taskqueue-send-email')
                taskqueue.add(url=email_url, params={
                    'to': user.email,
                    'subject': subject,
                    'body': email_body,
                    'sender': self.app.config.get('contact_sender'),
                })

                #Login User
                self.auth.get_user_by_password(user.auth_ids[0], password)
                self.add_message(_(messages.passwordchange_success), 'success')
                return self.redirect_to('materialize-settings-account')
            except (InvalidAuthIdError, InvalidPasswordError), e:
                # Returns error message to self.response.write in
                # the BaseHandler.dispatcher
                message = _(messages.password_wrong)
                self.add_message(message, 'danger')
                return self.redirect_to('materialize-settings-account')
        except (AttributeError, TypeError), e:
            login_error_message = _(messages.expired_session)
            self.add_message(login_error_message, 'danger')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        return forms.EditPasswordForm(self)

class MaterializeSettingsDeleteRequestHandler(BaseHandler):
    """
        Handler for materialized settings delete account
    """
    @user_required
    def post(self, **kwargs):
        # check captcha
        response = self.request.POST.get('g-recaptcha-response')
        remote_ip = self.request.remote_addr

        cResponse = captcha.submit(
            response,
            self.app.config.get('captcha_private_key'),
            remote_ip)

        if cResponse.is_valid:
            # captcha was valid... carry on..nothing to see here
            pass
        else:
            _message = _(messages.captcha_error)
            self.add_message(_message, 'danger')
            return self.redirect_to('materialize-settings-account')

        if not self.form.validate():
            message = _(messages.password_wrong)
            self.add_message(message, 'danger')
            return self.redirect_to('materialize-settings-account')

        password = self.form.password.data.strip()

        try:

            user_info = self.user_model.get_by_id(long(self.user_id))
            auth_id = "own:%s" % user_info.username
            password = utils.hashing(password, self.app.config.get('salt'))

            try:
                # authenticate user by its password
                user = self.user_model.get_by_auth_password(auth_id, password)
                if user:
                    # Delete Social Login
                    # for social in models_boilerplate.SocialUser.get_by_user(user_info.key):
                    #     social.key.delete()

                    user_info.key.delete()

                    ndb.Key("Unique", "User.username:%s" % user.username).delete_async()
                    ndb.Key("Unique", "User.auth_id:own:%s" % user.username).delete_async()
                    ndb.Key("Unique", "User.email:%s" % user.email).delete_async()

                    #TODO: Delete UserToken objects, Delete Home if Admin

                    self.auth.unset_session()

                    # display successful message
                    msg = _(messages.account_delete_success)
                    self.add_message(msg, 'success')
                    return self.redirect_to('materialize-home')
                else:
                    message = _(messages.password_wrong)
                    self.add_message(message, 'danger')
                    return self.redirect_to('materialize-settings-account')

            except (InvalidAuthIdError, InvalidPasswordError), e:
                # Returns error message to self.response.write in
                # the BaseHandler.dispatcher
                message = _(messages.password_wrong)
                self.add_message(message, 'danger')
                return self.redirect_to('materialize-settings-account')

        except (AttributeError, TypeError), e:
            login_error_message = _(messages.expired_session)
            self.add_message(login_error_message, 'danger')
            self.redirect_to('landing')

    @webapp2.cached_property
    def form(self):
        return forms.DeleteAccountForm(self)

class MaterializeTutorialsRequestHandler(BaseHandler):
    """
        Handler for materialized terms of use
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info = disclaim(self)
        return self.render_template('materialize/users/sections/tutorials.html', **params)




""" SMALL MEDIA handlers

    These handlers are used to serve small media files from datastore

"""
class MediaDownloadHandler(BaseHandler):
    """
    Handler for Serve Vendor's Logo
    """
    def get(self, kind, media_id):
        """ Handles download"""

        params = {}

        if kind == 'profile':
            user_info = self.user_model.get_by_id(long(media_id))        
            if user_info != None:
                if user_info.picture != None:
                    self.response.headers['Content-Type'] = 'image/png'
                    self.response.out.write(user_info.picture)


        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write('No image')




""" BIG MEDIA handlers

    These handlers operate files larger than the 1Mb, upload and serve.

"""
class BlobFormHandler(BaseHandler, blobstore_handlers.BlobstoreUploadHandler):
    """
        To better handle text inputs included in same file form, please refer to bp_admin/blog.py
    """
    @user_required
    def get(self):
        upload_url = blobstore.create_upload_url('/blobstore/upload/')
        self.response.out.write('<html><body>')
        self.response.out.write('<form action="%s" method="POST" enctype="multipart/form-data">' % upload_url)
        self.response.out.write('''Upload File: <input type="file" name="file"><br> <input type="submit"
            name="submit" value="Submit"> <input type="hidden" name="_csrf_token" value="%s"> </form></body></html>''' % self.session.get('_csrf_token'))

class BlobUploadHandler(blobstore_handlers.BlobstoreUploadHandler):
    def post(self):
        try:
            upload = self.get_uploads()[0]
            user_photo = models.Media(blob_key=upload.key())
            user_photo.put()
            self.redirect('/blobstore/serve/%s' % upload.key())
        except:
            self.error(404)

class BlobDownloadHandler(blobstore_handlers.BlobstoreDownloadHandler):
    def get(self, photo_key):
        if not blobstore.get(photo_key):
            self.error(404)
        else:
            self.send_blob(photo_key)




""" CRONJOB + TASKQUEUE handlers

    These handlers obey to cron.yaml in order to produce recurrent, autonomous tasks

"""
class WelcomeCronjobHandler(BaseHandler):
    def get(self):
        welcome_url = self.uri_for('taskqueue-welcome')
        taskqueue.add(url=welcome_url, params={
            'offset': 0
        })
        
class WelcomeHandler(BaseHandler):
    """
    Core Handler for sending users welcome message
    Use with TaskQueue
    """

    @taskqueue_method
    def post(self):
        count = 0
        offset = int(self.request.get("offset"))
        attempt = 1
        if (self.request.get("attempt")):
            attempt = int(self.request.get("attempt")) + 1

        #Case "One taskqueue, many homes"
        homes = models.Home.query()
        for home in homes:
            if home.cfe.rpu != -1 and home.cfe.connected and home.tips_email_counter == 0:
                logging.info("Welcoming Home ID: %s" % home.key.id())
                count += 1
                if count > offset:
                    try:
                        for habitant in home.habitant:
                            user_info = self.user_model.get_by_id(long(habitant))
                            if user_info != None:
                                _username = user_info.name
                                logging.info("Welcome message being sent to: %s" % user_info.email)
                                subject = messages.email_welcome_subject
                                template_val = {
                                    "username": _username,
                                    "_url": self.uri_for("history", _full=True),
                                    "support_url": self.uri_for("contact", _full=True),
                                    "faq_url": self.uri_for("faq", _full=True)
                                }
                                body_path = "emails/welcome.txt"
                                body = self.jinja2.render_template(body_path, **template_val)
                                email = user_info.email
                                email_url = self.uri_for('taskqueue-send-email')
                                
                                taskqueue.add(url=email_url, params={
                                    'to': str(user_info.email),
                                    'subject': subject,
                                    'body': body,
                                })

                        home.tips_email_counter = 1
                        home.tips_email_lastdate = date.today()
                        home.put()

                    except Exception, e:
                        logging.error("Error welcoming home: %s. Retrying taskqueue in 5 seconds." % e)
                        logging.info("Attempt number: %s" % attempt)
                        time.sleep(5)
                        if attempt < 10:
                            welcome_url = self.uri_for('taskqueue-welcome')
                            taskqueue.add(url=welcome_url, params={
                                'offset': count - 1,
                                'attempt': attempt,
                            })
                        else:
                            welcome_url = self.uri_for('taskqueue-welcome')
                            taskqueue.add(url=welcome_url, params={
                                'offset': count,
                            })
                        break




""" REST API preparation handlers

    These handlers obey to interactions with key-holder developers

"""
class APIIncomingHandler(BaseHandler):
    """
    Core Handler for incoming interactions
    """

    def post(self):
        KEY = "mwkMqTWFnK0LzJHyfkeBGoS2hr2KG7WhHqSGX0SbDJ4"
        SECRET = "152731fe2b14da111a72127d642e73c779e530b3"
        
        api_key = ""
        api_secret = ""
        args = self.request.arguments()
        for arg in args:
            logging.info("argument: %s" % arg)
            for key,value in json.loads(arg).iteritems():
                if key == "api_key":
                    api_key = value
                if key == "api_secret":
                    api_secret = value
                if key == "method":
                    if value == "101":
                        logging.info("parsing method 101")
                    elif value == "201":
                        logging.info("parsing method 201")

                        

        if api_key == KEY and api_secret == SECRET:
            logging.info("Attempt to receive incoming message with key: %s." % api_key)

            # DO SOMETHING WITH RECEIVED PAYLOAD

        else:
            logging.info("Attempt to receive incoming message without appropriate key: %s." % api_key)
            self.abort(403)

class APIOutgoingHandler(BaseHandler):
    """
    Core Handler for outgoing interactions with simpplo
    """

    def post(self):
        from google.appengine.api import urlfetch
        
        KEY = "mwkMqTWFnK0LzJHyfkeBGoS2hr2KG7WhHqSGX0SbDJ4"
        _URL = ""


        api_key = ""
        api_secret = ""
        args = self.request.arguments()
        for arg in args:
            logging.info("argument: %s" % arg)
            for key,value in json.loads(arg).iteritems():
                if key == "api_key":
                    api_key = value
                if key == "api_secret":
                    api_secret = value
                if key == "method":
                    if value == "101":
                        logging.info("parsing method 101")
                    elif value == "201":
                        logging.info("parsing method 201")
                        

        if api_key == KEY:
            logging.info("Attempt to send outgoing message with appropriate key: %s." % api_key)
            
            # DO SOMETHING WITH RECEIVED PAYLOAD
            #urlfetch.fetch(_URL, payload='', method='POST') 

        else:
            logging.info("Attempt to send outgoing message without appropriate key: %s." % api_key)
            self.abort(403)
       
class APITestingHandler(BaseHandler):
    """
    Core Handler for testing interactions with simpplo
    """

    def get(self):
        from google.appengine.api import urlfetch
        import urllib

        try:
            _url = self.uri_for('mbapi-out', _full=True)
            urlfetch.fetch(_url, payload='{"api_key": "mwkMqTWFnK0LzJHyfkeBGoS2hr2KG7WhHqSGX0SbDJ4","channel": "CHANNELHERE","container": "CONTENTSHERE"}', method="POST")
        except:
            pass
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write('Tests went good... =)')




""" WEB  static handlers

    These handlers are just to be a full website in the web background.

"""
class RobotsHandler(BaseHandler):
    def get(self):
        params = {
            'scheme': self.request.scheme,
            'host': self.request.host,
        }
        self.response.headers['Content-Type'] = 'text/plain'

        def set_variables(text, key):
            return text.replace("{{ %s }}" % key, params[key])

        self.response.write(reduce(set_variables, params, open("bp_content/themes/%s/templates/seo/robots.txt" % self.get_theme).read()))

class HumansHandler(BaseHandler):
    def get(self):
        params = {
            'scheme': self.request.scheme,
            'host': self.request.host,
        }
        self.response.headers['Content-Type'] = 'text/plain'

        def set_variables(text, key):
            return text.replace("{{ %s }}" % key, params[key])

        self.response.write(reduce(set_variables, params, open("bp_content/themes/%s/templates/seo/humans.txt" % self.get_theme).read()))

class SitemapHandler(BaseHandler):
    def get(self):
        params = {
            'scheme': self.request.scheme,
            'host': self.request.host,
        }
        self.response.headers['Content-Type'] = 'application/xml'

        def set_variables(text, key):
            return text.replace("{{ %s }}" % key, params[key])

        self.response.write(reduce(set_variables, params, open("bp_content/themes/%s/templates/seo/sitemap.xml" % self.get_theme).read()))

class CrossDomainHandler(BaseHandler):
    def get(self):
        params = {
            'scheme': self.request.scheme,
            'host': self.request.host,
        }
        self.response.headers['Content-Type'] = 'application/xml'

        def set_variables(text, key):
            return text.replace("{{ %s }}" % key, params[key])

        self.response.write(reduce(set_variables, params, open("bp_content/themes/%s/templates/seo/crossdomain.xml" % self.get_theme).read()))
