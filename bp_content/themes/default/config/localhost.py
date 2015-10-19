config = {

    # This config file will be detected in localhost environment and values defined here will overwrite those in config.py
    'environment': "localhost",

    # ----> ADD MORE CONFIGURATION OPTIONS HERE <----
    
    'app_name': "mboilertplate @localhost",
    
    
    'error_templates': {
        403: 'errors/default_error.html',
        404: 'errors/404.html',
        500: 'errors/500.html',
    },
    
     # contact page email settings
    'contact_sender': "SENDER_EMAIL_HERE",
    'contact_recipient': "RECIPIENT_EMAIL_HERE",
	
	
    # get your own recaptcha keys by registering at http://www.google.com/recaptcha/
    'captcha_public_key': "CAPTCHA_PUBLIC_KEY",
    'captcha_private_key': "CAPTCHA_PRIVATE_KEY",

    # Password AES Encryption Parameters
    # aes_key must be only 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes (characters) long.
    'aes_key': "12_24_32_BYTES_KEY_FOR_PASSWORDS",
    'salt': "_PUT_SALT_HERE_TO_SHA512_PASSWORDS_",

    # get your own consumer key and consumer secret by registering at https://dev.twitter.com/apps
    # callback url must be: http://[YOUR DOMAIN]/login/twitter/complete
    'twitter_consumer_key': 'TWITTER_CONSUMER_KEY',
    'twitter_consumer_secret': 'TWITTER_CONSUMER_SECRET',

    #Facebook Login
    # get your own consumer key and consumer secret by registering at https://developers.facebook.com/apps
    #Very Important: set the site_url= your domain in the application settings in the facebook app settings page
    # callback url must be: http://[YOUR DOMAIN]/login/facebook/complete
    'fb_api_key': 'FACEBOOK_API_KEY',
    'fb_secret': 'FACEBOOK_SECRET',
    
    # jinja2 base layout template
    #'base_layout': 'master.html',

    # send error emails to developers
    'send_mail_developer': False,

    # fellas' list
    'developers': (
        ('chuycepeda', 'chuycepeda@gmail.com'),
    ),

    
}