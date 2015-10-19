#Hello, this is magic ! #

*The materialize boilerplate project is an amazing fusion from material design, polymer web components, and boilerplate framework for easy and quick deployments of web applications on the Google Cloud Platform.*

###What's Materialize?
Materialize simplifies life for developers and the users they serve. It speeds up development, heavy lifting has been done for you to provide a smoother experience for visitors. ([showcase](http://materializecss.com/showcase.html))

###What's Polymer?
Polymer lets you build encapsulated, re-usable elements that work just like HTML elements, to use in building web applications. It makes it easier than ever to make fast, beautiful, and interoperable web components. ([polymer-project](https://www.polymer-project.org/1.0/))


###What's Boilerplate?
A Boilerplate is used to describe sections of code that can be reused over and over in new contexts or applications which provides good default values, reducing the need to specify program details in every project. ([wikipedia](http://en.wikipedia.org/wiki/Boilerplate_code))


---

#####Functions and features

+ Authentication (Sign In, Sign Out, Sign Up)
+ Federated Login - login via your favorite social network (Google, Twitter, etc...) powered by OpenID and OAuth
+ Reset Password
+ Update User Profile
+ Contact Form
+ Client side and server side form validation
+ Automatic detection of user language
+ Support for many Languages (English, Spanish, Italian, French, Chinese, Indonesian, German, Russian, etc)
+ Visitors Log
+ Notifications and Confirmation for users when they change their email or password
+ Responsive Design for viewing on PCs, tablets, and mobile phones (synchronized with Twitter-Bootstrap project)
+ Mobile identification
+ Unit Testing
+ Error handling
+ Basic user management features available under /admin/users/ for Google Application Administrators

#####Technologies used
+ [Python 2.7.5](https://www.python.org/download/releases/2.7.5/)
+ [NDB 1.0.10](http://developers.google.com/appengine/docs/python/ndb/) (The best datastore API for the Google App Engine Python runtime).
+ [Jinja2 2.6](http://jinja.pocoo.org/docs/) (A fully featured template engine for Python).
+ [WTForms-1.0.2](http://wtforms.simplecodes.com/) (Forms validation framework keeping user interaction secure and flexible with or without javascript).
+ [Babel-0.9.6](http://babel.edgewall.org/) and [gaepytz-2011h](http://code.google.com/p/gae-pytz/) (Industy standard internationalization renders the site in multiple languages).
+ [webapp2 2.5.2](http://webapp-improved.appspot.com/) (A lightweight Python web framework, the most compatible with Google App Engine).
    + webapp2_extras.sessions
    + webapp2_extras.routes
    + webapp2_extras.auth
    + webapp2_extras.i18n
+ Code written following the [Google Python Style Guide](http://google-styleguide.googlecode.com/svn/trunk/pyguide.html)
+ Unit testing with [unittest](http://docs.python.org/library/unittest.html), [webtest](http://webtest.pythonpaste.org/en/latest/index.html), [pyquery](http://packages.python.org/pyquery/)
+ OpenID library provided by Google App Engine
+ OAuth2 for federated login providers that do not support OpenID

#####Front-end Technologies
+ [HTML5Boilerplate](http://html5boilerplate.com/)
+ [Modernizr 2.6.1](http://modernizr.com)
+ [jQuery 2.1.1](http://jquery.com)
+ [MaterializeCSS](http://materializecss.com/)
+ [Polymer](https://www.polymer-project.org/1.0/)

#####Interesting integrations
+ [Bit.ly](https://bitly.com)
+ [Goo.gl](http://goo.gl/)
+ [Slack](http://slack.com)
+ [Sendgrid](http://sendgrid.com)
+ [CartoDB](http://cartodb.com)


#####Security
**SSL**

+ SSL is enabled site wide by adding <tt>secure: always</tt> to the section: <tt>- url: /.*</tt> in app.yaml (remove this line to disable)
+ SSL either requires a free google app engine *.appspot.com domain or a [custom domain and certificate](https://developers.google.com/appengine/docs/ssl)
+ Alternatively SSL can be enabled at a controller level via webapp2 schemes. Use the secure_scheme provided in routes.py
+ It is recommended to enable ssl site wide to help prevent [session hijacking](http://en.wikipedia.org/wiki/Session_hijacking)

**Passwords**

+ Passwords are hashed and encrypted with SHA512 and PyCrypto.

**CSRF**

+ [Cross-site request forgery](http://en.wikipedia.org/wiki/Cross-site_request_forgery) protection