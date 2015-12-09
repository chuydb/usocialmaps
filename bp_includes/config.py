"""
============= DON'T MODIFY THIS FILE ============
This is the boilerplate default configuration file.
Changes and additions to settings should be done in
/bp_content/themes/<YOUR_THEME>/config/ rather than this config.
"""

import os

config = {

    # webapp2 sessions
    'webapp2_extras.sessions': {'secret_key': '_PUT_KEY_HERE_YOUR_SECRET_KEY_'},

    # webapp2 authentication
    'webapp2_extras.auth': {'user_model': 'bp_includes.models.User',
                            'cookie_name': 'session_name'},

    # jinja2 templates
    'webapp2_extras.jinja2': {'template_path': ['bp_admin/templates', 'bp_content/themes/%s/templates' % os.environ['theme']],
                              'environment_args': {'extensions': ['jinja2.ext.i18n']}},

    # application name
    'app_name': 'Social Maps',
    'twitter_url': '',
    'facebook_url': '',
    'meta_tags_code': """
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
            <meta name="description" content="This an amazing, magical materialized boilerplate for the Google AppEngine." />
            <meta name="keywords" content="mboilerplate, appengine, materialize, boilerplate, webcomponents, google cloud, gae"/>
            <meta property="og:site_name" content="usocialmaps.appspot.com"/>
            <meta property="og:title" content="MBoilerplate"/>
            <meta property="og:type" content="website"/>
            <meta property="og:description" content="This an amazing, magical materialized boilerplate for the Google AppEngine."/>
            <meta property="og:url" content="http://usocialmaps.appspot.com"/>
            <meta property="og:image" content="http://usocialmaps.appspot.com/{{theme}}/materialize/images/landing/map.png"/>
            <meta name="twitter:card" content="summary_large_image">
            <meta name="twitter:site" content="This an amazing, magical materialized boilerplate for the Google AppEngine.">
            <meta name="twitter:creator" content="@chuycepeda">
            <meta name="twitter:title" content="MBoilerplate">
            <meta name="twitter:description" content="This an amazing, magical materialized boilerplate for the Google AppEngine.">
            <meta name="twitter:image" content="http://usocialmaps.appspot.com/{{theme}}/materialize/images/landing/map.png">
            <meta property="twitter:url" content="http://usocialmaps.appspot.com"/>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="viewport" content="width=device-width, minimum-scale=1.0, initial-scale=1.0, user-scalable=yes">""",

    # the default language code for the application.
    # should match whatever language the site uses when i18n is disabled
    'app_lang': 'en',


    # jinja2 base layout template
    'base_layout': '/materialize/landing/base.html',
    'landing_layout': '/materialize/landing/base.html',

    # Locale code = <language>_<territory> (ie 'en_US')
    # to pick locale codes see http://cldr.unicode.org/index/cldr-spec/picking-the-right-language-code
    # also see http://www.sil.org/iso639-3/codes.asp
    # Language codes defined under iso 639-1 http://en.wikipedia.org/wiki/List_of_ISO_639-1_codes
    # Territory codes defined under iso 3166-1 alpha-2 http://en.wikipedia.org/wiki/ISO_3166-1
    # disable i18n if locales array is empty or None
    'locales': ['en_US', 'es_ES', 'it_IT', 'zh_CN', 'id_ID', 'fr_FR', 'de_DE', 'ru_RU', 'pt_BR', 'cs_CZ','vi_VN','nl_NL'],

    # contact page email settings
    'contact_sender': '',
    'contact_recipient': '',

    # Password AES Encryption Parameters
    # aes_key must be only 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes (characters) long.
    'aes_key': "12_24_32_BYTES_KEY_FOR_PASSWORDS",
    'salt': "_PUT_SALT_HERE_TO_SHA512_PASSWORDS_",

    # get your own consumer key and consumer secret by registering at https://dev.twitter.com/apps
    # callback url must be: http://[YOUR DOMAIN]/login/twitter/complete
    'twitter_consumer_key': '',
    'twitter_consumer_secret': '',

    #Facebook Login
    # get your own consumer key and consumer secret by registering at https://developers.facebook.com/apps
    #Very Important: set the site_url= your domain in the application settings in the facebook app settings page
    # callback url must be: http://[YOUR DOMAIN]/login/facebook/complete
    'fb_api_key': '',
    'fb_secret': '',

    #Linkedin Login
    #Get you own api key and secret from https://www.linkedin.com/secure/developer
    'linkedin_api': '',
    'linkedin_secret': '',

    # Github login
    # Register apps here: https://github.com/settings/applications/new
    'github_server': 'github.com',
    'github_redirect_uri': 'http://www.example.com/social_login/github/complete',
    'github_client_id': '',
    'github_client_secret': '',

    # get your own recaptcha keys by registering at http://www.google.com/recaptcha/
    'captcha_public_key': '',
    'captcha_private_key': '',

    # Use a complete Google Analytics code, no just the Tracking ID
    # In config/boilerplate.py there is an example to fill out this value
    'google_analytics_code': '',

    # add status codes and templates used to catch and display errors
    # if a status code is not listed here it will use the default app engine
    # stacktrace error page or browser error page
    'error_templates': {
        403: 'errors/default_error.html',
        404: 'errors/404.html',
        500: 'errors/500.html',
    },

    # Enable Federated login (OpenID and OAuth)
    # Google App Engine Settings must be set to Authentication Options: Federated Login
    'enable_federated_login': True,

    # send error emails to developers
    'send_mail_developer': False,

    # fellas' list
    'developers': (
        ('Santa Klauss', 'snowypal@northpole.com'),
    ),

    # If true, it will write in datastore a log of every email sent
    'log_email': True,

    # If true, it will write in datastore a log of every visit
    'log_visit': True,

    # ----> ADD MORE CONFIGURATION OPTIONS HERE <----

    #branding stuff
    'brand_logo': '/default/materialize/images/logoH.png',
    'brand_favicon': '/default/materialize/images/logo.png',
    'brand_color' : 'sm-green',

    #bitly integration
    'bitly_login' : '',
    'bitly_apikey' : '',

    #sendgrid integration
    'sendgrid_login' : '',
    'sendgrid_passkey' : '',

    #slack webhook integration
    'slack_webhook_url' : '',
    'slack_notify_user' : '',
    'slack_notify_home_visit' : '',
    'slack_notify_landing_visit' : '',

    #cartodb integration
    'cartodb_user': 'usocialmaps',
    'cartodb_apikey': '837d88435bf651da10db661dad2a2480c0b171d8',
    'cartodb_reports_table': 'public_reports',

    #zendesk integration
    'zendesk_imports': '',
    #EXAMPLE OF ZENDESK IMPORTS
    # """<style type="text/css" media="screen, projection">
    #               @import url(//assets.zendesk.com/external/zenbox/v2.6/zenbox.css);
    #             </style>"""
    'zendesk_code': '',
    #EXAMPLE OF ZENDESK CODE
    # """<script type="text/javascript" src="//assets.zendesk.com/external/zenbox/v2.6/zenbox.js"></script>
    #             <script>
    #                 if (typeof(Zenbox) !== "undefined") {
    #                     Zenbox.init({
    #                       dropboxID:   "20172435",
    #                       url:         "https://invictusmx.zendesk.com",
    #                       tabTooltip:  "Feedback",
    #                       tabImageURL: "https://p4.zdassets.com/external/zenbox/images/tab_es_feedback_right.png",
    #                       tabColor:    "#ff0000",
    #                       tabPosition: "Right",
    #                       hide_tab: true,
    #                     });

    #                 }
    #                 if (document.querySelector('#zen_alias'))
    #                     document.querySelector('#zen_alias').addEventListener('click', function() { window.Zenbox.show();});
    #                 if (document.querySelector('#chat_alias'))
    #                     document.querySelector('#chat_alias').addEventListener('click', function() { window.Zenbox.show();});
    #             </script>"""

    #mailchimp integration
    'mailchimp_code': '',



} # end config
