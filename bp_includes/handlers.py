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
                "twitter_url": self.app.config.get('twitter_url'),
                "facebook_url": self.app.config.get('facebook_url'),
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
            return self.redirect_to('landing')

        else:
            self.add_message(_(messages.passwords_mismatch), 'danger')
            return self.redirect_to('password-reset-check', user_id=user_id, token=token)

    @webapp2.cached_property
    def form(self):
        return forms.PasswordResetCompleteForm(self)




""" REGISTRATION handlers 

    These handlers concern registration in 2 ways: direct, or from referral.

"""
class MaterializeRegisterRequestHandler(BaseHandler):
    """
    Handler for Sign Up Users
    """

    def get(self):
        """ Returns a simple HTML form for create a new user """

        if self.user:
            self.redirect_to('landing')

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
                        "twitter_url": self.app.config.get('twitter_url'),
                        "facebook_url": self.app.config.get('facebook_url'),
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
            # long_url = self.uri_for("register-referral",user_id=user.get_id(),_full=True)
            # logging.info("Long URL: %s" % long_url)
            
            #The goo.gl way:
            # post_url = 'https://www.googleapis.com/urlshortener/v1/url'            
            # payload = {'longUrl': long_url}
            # headers = {'content-type': 'application/json'}
            # r = requests.post(post_url, data=json.dumps(payload), headers=headers)
            # j = json.loads(r.text)
            # logging.info("Google response: %s" % j)
            # short_url = j['id']

            #The bit.ly way:
            # api = bitly.Api(login=self.app.config.get('bitly_login'), apikey=self.app.config.get('bitly_apikey'))
            # short_url=api.shorten(long_url)
            # logging.info("Bitly response: %s" % short_url)

            # user.link_referral = short_url
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
                    "twitter_url": self.app.config.get('twitter_url'),
                    "facebook_url": self.app.config.get('facebook_url'),
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
                return self.redirect_to('landing')

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
    _params['has_address'] = True if user_info.address is not None else False
    _params['address_from'] = False
    if _params['has_address']:
        if user_info.address.address_from_coord is not None:
            lat = str(user_info.address.address_from_coord.lat)
            lng = str(user_info.address.address_from_coord.lon)
            _params['address_from_coord'] = lat + "," + lng
        _params['address_from'] = user_info.address.address_from
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

# REPORT
class MaterializeNewReportHandler(BaseHandler):
    """
    Handler for materialized home
    """  
    @user_required
    def get(self):
        """ Returns a simple HTML form for materialize home """
        ####-------------------- P R E P A R A T I O N S --------------------####
        if self.user:
            params, user_info = disclaim(self)
        else:
            params = {}
        ####------------------------------------------------------------------####
        
        return self.render_template('materialize/landing/new_report.html', **params)

    @user_required
    def post(self):
        """ Get fields from POST dict """
                        
        address_from = self.request.get('address_from')
        address_from_coord = self.request.get('address_from_coord')
        catGroup = self.request.get('catGroup')
        subCat = self.request.get('subCat')
        description = self.request.get('description')
        title = self.request.get('title')
        video_url = self.request.get('video_url')
        kind = self.request.get('kind')
        
        try:
            user_report = models.Report()
            user_report.user_id = int(self.user_id) if int(self.user_id) is not None else -1
            user_report.address_from_coord = ndb.GeoPt(address_from_coord)
            user_report.address_from = address_from
            user_report.title = title
            user_report.kind = kind
            user_report.video_url = video_url
            user_report.description = description
            user_report.likeability = catGroup
            user_report.feeling  = subCat
            user_report.put()
            
            #PUSH TO CARTODB
            from google.appengine.api import urlfetch
            import urllib
            api_key = self.app.config.get('cartodb_apikey')
            cartodb_domain = self.app.config.get('cartodb_user')
            cartodb_table = self.app.config.get('cartodb_reports_table')
            #INSERT
            unquoted_url = ("https://%s.cartodb.com/api/v2/sql?q=INSERT INTO %s (the_geom, title, description, address, image_url, likeability, feeling, follows, uuid, created, kind, video_url) VALUES (ST_GeomFromText('POINT(%s %s)', 4326),'%s','%s','%s','%s','%s','%s',%s,'%s','%s','%s','%s')&api_key=%s" % (cartodb_domain, cartodb_table, user_report.address_from_coord.lon, user_report.address_from_coord.lat, user_report.title,user_report.description,user_report.address_from,user_report.image_url,user_report.likeability,user_report.feeling,user_report.follows,user_report.key.id(), user_report.created.strftime("%Y-%m-%d"),user_report.kind,user_report.video_url,api_key)).encode('utf8')
            url = urllib.quote(unquoted_url, safe='~@$&()*!+=:;,.?/\'')
            t = urlfetch.fetch(url)
            logging.info("t: %s" % t.content)

            #SELECT CARTODB_ID & ASSIGN
            cl = CartoDBAPIKey(api_key, cartodb_domain)
            response = cl.sql('select cartodb_id from %s order by cartodb_id desc limit 1' % cartodb_table)
            user_report.cdb_id = response['rows'][0]['cartodb_id']

            user_report.put()

            if hasattr(self.request.POST['file'], 'filename'):
                #create attachment
                from google.appengine.api import urlfetch
                from poster.encode import multipart_encode, MultipartParam
                
                urlfetch.set_default_fetch_deadline(45)

                payload = {}
                upload_url = blobstore.create_upload_url('/report/image/upload/%s' %(user_report.key.id()))
                file_data = self.request.POST['file']
                payload['file'] = MultipartParam('file', filename=file_data.filename,
                                                         filetype=file_data.type,
                                                         fileobj=file_data.file)
                data,headers= multipart_encode(payload)
                t = urlfetch.fetch(url=upload_url, payload="".join(data), method=urlfetch.POST, headers=headers)
                
                logging.info('t.content: %s' % t.content)
                
                if t.content == 'success':
                    message = _(messages.report_success)
                    self.add_message(message, 'success')
                    return self.redirect_to('materialize-report-success')
                else:
                    message = _(messages.attach_error)
                    self.add_message(message, 'danger')            
                    return self.get()                    
            else:
                message = _(messages.report_success)
                self.add_message(message, 'success')
                return self.redirect_to('materialize-report-success')

        except Exception as e:
            logging.info('error in post: %s' % e)
            message = _(messages.saving_error)
            self.add_message(message, 'danger')
            return self.get()

class MaterializeReportUploadImageHandler(blobstore_handlers.BlobstoreUploadHandler):
    def post(self, report_id):
        try:
            logging.info(self.get_uploads()[0])
            logging.info('attaching file to report_id: %s' %report_id)
            upload = self.get_uploads()[0]
            report = models.Report.get_by_id(long(report_id))
            # report.attachment = upload.key()
            report.image_url = self.uri_for('blob-serve', photo_key = upload.key(), _full=True)
            report.put()

            if report.cdb_id != -1:
                #UPDATE CARTODB
                from google.appengine.api import urlfetch
                import urllib
                api_key = self.app.config.get('cartodb_apikey')
                cartodb_domain = self.app.config.get('cartodb_user')
                cartodb_table = self.app.config.get('cartodb_reports_table')
                unquoted_url = ("https://%s.cartodb.com/api/v2/sql?q=UPDATE %s SET image_url = '%s' WHERE cartodb_id = %s &api_key=%s" % (cartodb_domain, cartodb_table, report.image_url, report.cdb_id, api_key)).encode('utf8')
                url = urllib.quote(unquoted_url, safe='~@$&()*!+=:;,.?/\'')
                t = urlfetch.fetch(url)
                logging.info("t: %s" % t.content)

            self.response.headers['Content-Type'] = 'text/plain'
            self.response.out.write('success')
        except Exception as e:
            logging.error('something went wrong: %s' % e)
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.out.write('error')

class MaterializeNewReportSuccessHandler(BaseHandler):
    """
    Handler for materialized home
    """  
    def get(self):
        """ Returns a simple HTML form for materialize home """
        ####-------------------- P R E P A R A T I O N S --------------------####
        if self.user:
            params, user_info = disclaim(self)
        else:
            params = {}
        ####------------------------------------------------------------------####
        
        return self.render_template('materialize/landing/new_report_success.html', **params)

class MaterializeFollowRequestHandler(BaseHandler):
    def post(self):
        report_id = int(self.request.get('report_id'))
        user_id = int(self.request.get('user_id'))
        kind = self.request.get('kind')
        reportDict = {}

        try:
            report = models.Report.get_by_cdb(int(report_id))
            if report:
                if kind == 'follow' and report.user_id != int(user_id):
                    follower = models.Followers.query(ndb.AND(models.Followers.user_id == long(user_id),models.Followers.report_id == long(report_id)))
                    if follower.count() == 0 and report:
                        _u = models.User.get_by_id(long(user_id))
                        if _u:
                            follower = models.Followers()
                            follower.user_id = user_id
                            follower.report_id = report_id
                            follower.put()
                            report.follows += 1
                            report.put()
                            #UPDATE CARTO
                            from google.appengine.api import urlfetch
                            import urllib
                            api_key = self.app.config.get('cartodb_apikey')
                            cartodb_domain = self.app.config.get('cartodb_user')
                            cartodb_table = self.app.config.get('cartodb_reports_table')
                            unquoted_url = ("https://%s.cartodb.com/api/v2/sql?q=UPDATE %s SET follows = %s WHERE cartodb_id = %s &api_key=%s" % (cartodb_domain, cartodb_table, report.follows, report_id, api_key)).encode('utf8')
                            url = urllib.quote(unquoted_url, safe='~@$&()*!+=:;,.?/\'')
                            t = urlfetch.fetch(url)
                            reportDict['contents'] = 'follow request successful'
                    elif follower.count() == 1:
                        reportDict['contents'] = 'user already following'
                    reportDict['status'] = 'success'
                elif kind == 'unfollow' and report.user_id != int(user_id):
                    follower = models.Followers.query(ndb.AND(models.Followers.user_id == long(user_id),models.Followers.report_id == long(report_id)))
                    if follower.count > 0:
                        for _f in follower:
                            _f.key.delete()
                            report.follows -= 1
                            report.follows = 0 if report.follows < 0 else report.follows
                            report.put()
                            #UPDATE CARTO
                            from google.appengine.api import urlfetch
                            import urllib
                            api_key = self.app.config.get('cartodb_apikey')
                            cartodb_domain = self.app.config.get('cartodb_user')
                            cartodb_table = self.app.config.get('cartodb_reports_table')
                            unquoted_url = ("https://%s.cartodb.com/api/v2/sql?q=UPDATE %s SET follows = %s WHERE cartodb_id = %s &api_key=%s" % (cartodb_domain, cartodb_table, report.follows, report_id, api_key)).encode('utf8')
                            url = urllib.quote(unquoted_url, safe='~@$&()*!+=:;,.?/\'')
                            t = urlfetch.fetch(url)
                    reportDict['status'] = 'success'
                    reportDict['contents'] = 'unfollow request successful'
                elif report.user_id == int(user_id):
                    reportDict['status'] = 'success'
                    reportDict['contents'] = 'user is creator'
                    reportDict['report_id'] = report_id
                    reportDict['user_id'] = user_id
                    reportDict['kind'] = kind
            else:
                reportDict['status'] = 'success'
                reportDict['contents'] = 'nothing to do here'
                reportDict['report_id'] = report_id
                reportDict['user_id'] = user_id
                reportDict['kind'] = kind
        except Exception as e:
            reportDict['status'] = 'error'
            reportDict['contents'] = '%s' % e
            pass



        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        self.response.headers['Content-Type'] = 'application/json'
        self.response.write(json.dumps(reportDict))

class MaterializeReportCommentsHandler(BaseHandler):
    def get(self,report_id):
        reportDict = {}
        logs = models.Comments.query(models.Comments.report_id == int(report_id))
        logs = logs.order(models.Comments.created)
        q = self.request.get('q')
        if q == 'count':
            reportDict['count'] = logs.count()
        else:
            html = '<ul class="collection" style="overflow:scroll;">'
            for log in logs:
                user = log.get_user()            
                if user:
                    image = user.get_image_url()
                    initial_letter = user.name[1]
                    name = user.name
                else:
                    image = -1
                    initial_letter = log.user_email[1]
                    name = ''
                html+= '<li class="collection-item avatar" style="height: auto;  display:inline-block; width: 100%; border: 1px solid white;">'
                if image != -1:
                    html+= '<img src="%s" alt="" class="circle" style="width: 60px;height: 60px;">' % image
                else:
                    html+= '<i class="mdi-action-face-unlock circle"></i>'
                html+= '<span class="title left" style="margin-left:20px"><span class="sm-yellow-text">%s:</span></span><br><p class="left" style="margin-left:20px"><span class="sm-blue-text">%s</span><br>%s</p>' % (name, log.get_formatted_date(), log.contents)
                html+= '</li>'
            html += '</ul>'
            reportDict['logs'] = {
                'html': html
            }
        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        self.response.headers['Content-Type'] = 'application/json'
        self.response.write(json.dumps(reportDict))

class MaterializeReportsRequestHandler(BaseHandler):
    """
        Handler for materialized reports
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info = disclaim(self)

        def get_video_url(url):
            if url:
                logging.info('url: %s' % url)
                if 'embed' in url:
                    return url
                else:
                    return 'https://www.youtube.com/embed/%s' % url.split('=')[-1]

        user_reports = models.Report.query(models.Report.user_id == int(user_info.key.id()))
        user_reports = user_reports.order(-models.Report.created)
        user_reports = user_reports.fetch(50)
        if user_reports is not None:
            try:
                params['reports'] = []
                for report in user_reports:
                    params['reports'].append((report.key.id(), report.title, report.created, report.address_from_coord, report.address_from, report.description, report.image_url, report.likeability, report.feeling, report.cdb_id, report.follows, report.get_log_count(), report.get_color(), 'own', report.kind, get_video_url(report.video_url)))
                try:
                    follows = models.Followers.query(models.Followers.user_id == int(user_info.key.id()))
                    for follow in follows:
                        report = models.Report.get_by_cdb(int(follow.report_id))
                        if report:
                            params['reports'].append((report.key.id(), report.title, report.created, report.address_from_coord, report.address_from, report.description, report.image_url, report.likeability, report.feeling, report.cdb_id, report.follows, report.get_log_count(), report.get_color(), 'follow', report.kind, get_video_url(report.video_url)))
                except:
                    pass
            except Exception as e:
                logging.error('error at: %s' % e)
                self.add_message(login_error_message, 'danger')
                self.redirect_to('login')

        return self.render_template('materialize/users/reports.html', **params)

    @user_required
    def post(self):
        delete = self.request.get('delete')
        report_id = self.request.get('report_id')
        
        try:
            if delete == 'confirmed_comment':
                user_info = self.user_model.get_by_id(long(self.user_id))
                report_info = models.Report.get_by_id(long(report_id))
                if report_info:
                    log_info = models.Comments()
                    log_info.user_email = user_info.email.lower()
                    log_info.report_id = int(report_id)
                    log_info.contents = self.request.get('comment')
                    log_info.put()                

            self.add_message(messages.inquiry_success, 'success')
            return self.get()

        except (AttributeError, KeyError, ValueError), e:
            logging.error('Error updating report: %s ' % e)
            self.add_message(messages.saving_error, 'danger')
            return self.get()

class MaterializeReportCommentsAddHandler(BaseHandler):
    @user_required
    def get(self):
        reportDict = {}
        report_id = self.request.get('report_id')
        comments = self.request.get('comment')

        try:
            user_info = self.user_model.get_by_id(long(self.user_id))
            report_info = models.Report.get_by_id(long(report_id))
            if report_info:
                log_info = models.Comments()
                log_info.user_email = user_info.email.lower()
                log_info.report_id = int(report_id)
                log_info.contents = comments
                log_info.put()                

            reportDict['status'] = 'success'

        except (AttributeError, KeyError, ValueError), e:
            logging.error('Error updating report: %s ' % e)
            reportDict['status'] = 'error: %s' % e
            pass

        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        self.response.headers['Content-Type'] = 'application/json'
        self.response.write(json.dumps(reportDict))

# USER
class MaterializeSettingsProfileRequestHandler(BaseHandler):
    """
        Handler for materialized settings profile
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info = disclaim(self)
        if not params['address_from']:
            params['address_from'] = ""
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
        address_from = self.request.get('address_from')
        address_from_coord = self.request.get('address_from_coord')
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
                if address_from is not None:
                    user_info.address = models.Address()
                    user_info.address.address_from = address_from
                    if len(address_from_coord.split(',')) == 2:
                        user_info.address.address_from_coord = ndb.GeoPt(address_from_coord)
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
                        "twitter_url": self.app.config.get('twitter_url'),
                        "facebook_url": self.app.config.get('facebook_url'),
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
            self.redirect_to('landing')

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
            self.redirect_to('landing')

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
                    "twitter_url": self.app.config.get('twitter_url'),
                    "facebook_url": self.app.config.get('facebook_url'),
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
                    return self.redirect_to('landing')
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
                sender = "%s Mail <no-reply@%s.appspotmail.com>" % (self.app.config.get('app_name'),app_id)                

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


""" WEB  static handlers

    These handlers are just to be a full website in the web background.

"""
class MBoiUsersHandler(BaseHandler):
    def get(self):
        reportDict = {}
        try:
            users = self.user_model.query()
            reportDict['status'] = 'success'
            reportDict['users'] = users.count()
            reportDict['exception'] = ''
            
        except Exception as e:
            reportDict['status'] = 'error'
            reportDict['users'] = 0
            reportDict['exception'] = '%s' % e

        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        self.response.headers['Content-Type'] = 'application/json'
        self.response.write(json.dumps(reportDict))
        
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
