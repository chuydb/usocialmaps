import sys
from socket import timeout
from .sgversion import __version__
import io
import sys
import json
try:
    import urllib.request as urllib_request
    from urllib.parse import urlencode
    from urllib.error import HTTPError
except ImportError:  # Python 2
    import urllib2 as urllib_request
    from urllib2 import HTTPError
    from urllib import urlencode
try:
    import rfc822
except Exception as e:
    import email.utils as rfc822

class SMTPAPIHeader(object):

    def __init__(self):
        self.data = {}

    def add_to(self, to):
        if 'to' not in self.data:
            self.data['to'] = []
        if type(to) is list:
            self.data['to'] += to
        else:
            self.data['to'].append(to)

    def set_tos(self, tos):
        self.data['to'] = tos

    def add_substitution(self, key, value):
        if 'sub' not in self.data:
            self.data['sub'] = {}
        if key not in self.data['sub']:
            self.data['sub'][key] = []
        self.data['sub'][key].append(value)

    def set_substitutions(self, subs):
        self.data['sub'] = subs

    def add_unique_arg(self, key, value):
        if 'unique_args' not in self.data:
            self.data['unique_args'] = {}
        self.data['unique_args'][key] = value

    def set_unique_args(self, value):
        self.data['unique_args'] = value

    def add_category(self, category):
        if 'category' not in self.data:
            self.data['category'] = []
        self.data['category'].append(category)

    def set_categories(self, category):
        self.data['category'] = category

    def add_section(self, key, section):
        if 'section' not in self.data:
            self.data['section'] = {}
        self.data['section'][key] = section

    def set_sections(self, value):
        self.data['section'] = value

    def add_send_each_at(self, time):
        if 'send_each_at' not in self.data:
          self.data['send_each_at'] = []
        self.data['send_each_at'].append(time)

    def set_send_each_at(self, time):
      self.data['send_each_at'] = time

    def set_send_at(self, time):
      self.data['send_at'] = time

    def add_filter(self, app, setting, val):
        if 'filters' not in self.data:
            self.data['filters'] = {}
        if app not in self.data['filters']:
            self.data['filters'][app] = {}
        if 'settings' not in self.data['filters'][app]:
            self.data['filters'][app]['settings'] = {}
        self.data['filters'][app]['settings'][setting] = val

    def set_asm_group_id(self, value):
        if not bool(value):
            self.data['asm_group_id'] = {}
        else:
            self.data['asm_group_id'] = value

    def json_string(self):
        result = {}
        for key in self.data.keys():
            if self.data[key] != [] and self.data[key] != {}:
                result[key] = self.data[key]
        return json.dumps(result)

class SendGridError(Exception):

    """Base class for SendGrid-related errors."""


class SendGridClientError(SendGridError):

    """Client error, which corresponds to a 4xx HTTP error."""


class SendGridServerError(SendGridError):

    """Server error, which corresponds to a 5xx HTTP error."""

class SendGridClient(object):

    """SendGrid API."""

    def __init__(self, username, password, **opts):
        """
        Construct SendGrid API object.

        Args:
            username: SendGrid username
            password: SendGrid password
            user: Send mail on behalf of this user (web only)
            raise_errors: If set to False (default): in case of error, `.send`
                method will return a tuple (http_code, error_message). If set
                to True: `.send` will raise SendGridError. Note, from version
                1.0.0, the default will be changed to True, so you are
                recommended to pass True for forwards compatability.
        """
        self.username = username
        self.password = password
        self.useragent = 'sendgrid/' + __version__ + ';python'
        self.host = opts.get('host', 'https://api.sendgrid.com')
        self.port = str(opts.get('port', '443'))
        self.endpoint = opts.get('endpoint', '/api/mail.send.json')
        self.mail_url = self.host + ':' + self.port + self.endpoint
        self._raise_errors = opts.get('raise_errors', False)
        # urllib cannot connect to SSL servers using proxies
        self.proxies = opts.get('proxies', None)

    def _build_body(self, message):
        if sys.version_info < (3, 0):
            ks = ['from_email', 'from_name', 'subject',
                  'text', 'html', 'reply_to']
            for k in ks:
                v = getattr(message, k)
                if isinstance(v, unicode):
                    setattr(message, k, v.encode('utf-8'))

        values = {
            'api_user': self.username,
            'api_key': self.password,
            'to[]': message.to if message.to else [message.from_email],
            'toname[]': message.to_name,
            'cc[]': message.cc,
            'bcc[]': message.bcc,
            'from': message.from_email,
            'fromname': message.from_name,
            'subject': message.subject,
            'text': message.text,
            'html': message.html,
            'replyto': message.reply_to,
            'headers': message.headers,
            'date': message.date,
            'x-smtpapi': message.json_string()
        }
        for k in list(values.keys()):
            if not values[k]:
                del values[k]
        for filename in message.files:
            if message.files[filename]:
                values['files[' + filename + ']'] = message.files[filename]
        for content in message.content:
            if message.content[content]:
                values['content[' + content + ']'] = message.content[content]
        return values

    def _make_request(self, message):
        if self.proxies:
            proxy_support = urllib_request.ProxyHandler(self.proxies)
            opener = urllib_request.build_opener(proxy_support)
            urllib_request.install_opener(opener)
        data = urlencode(self._build_body(message), True).encode('utf-8')
        req = urllib_request.Request(self.mail_url, data)
        req.add_header('User-Agent', self.useragent)
        response = urllib_request.urlopen(req, timeout=10)
        body = response.read()
        return response.getcode(), body

    def send(self, message):
        if self._raise_errors:
            return self._raising_send(message)
        else:
            return self._legacy_send(message)

    def _legacy_send(self, message):
        try:
            return self._make_request(message)
        except HTTPError as e:
            return e.code, e.read()
        except timeout as e:
            return 408, e

    def _raising_send(self, message):
        try:
            return self._make_request(message)
        except HTTPError as e:
            if 400 <= e.code < 500:
                raise SendGridClientError(e.code, e.read())
            elif 500 <= e.code < 600:
                raise SendGridServerError(e.code, e.read())
            else:
                assert False
        except timeout as e:
            raise SendGridClientError(408, 'Request timeout')

class Mail():

    """SendGrid Message."""

    def __init__(self, **opts):
        """
        Constructs SendGrid Message object.

        Args:
            to: Recipient
            to_name: Recipient name
            from_email: Sender email
            from_name: Sender name
            subject: Email title
            text: Email body
            html: Email body
            bcc: Recipient
            reply_to: Reply address
            date: Set date
            headers: Set headers
            files: Attachments
        """
        self.to = []
        self.to_name = []
        self.cc = []
        self.add_to(opts.get('to', []))
        self.add_to_name(opts.get('to_name', []))
        self.add_cc(opts.get('cc', []))
        self.from_email = opts.get('from_email', '')
        self.from_name = opts.get('from_name', '')
        self.subject = opts.get('subject', '')
        self.text = opts.get('text', '')
        self.html = opts.get('html', '')
        self.bcc = []
        self.add_bcc(opts.get('bcc', []))
        self.reply_to = opts.get('reply_to', '')
        self.files = opts.get('files', {})
        self.set_headers(opts.get('headers', ''))
        self.date = opts.get('date', rfc822.formatdate())
        self.content = opts.get('content', {})
        self.smtpapi = opts.get('smtpapi', SMTPAPIHeader())

    def parse_and_add(self, to):
        name, email = rfc822.parseaddr(to.replace(',', ''))
        if email:
            self.to.append(email)
        if name:
            self.add_to_name(name)

    def add_to(self, to):
        if isinstance(to, str):
            self.parse_and_add(to)
        elif sys.version_info < (3, 0) and isinstance(to, unicode):
            self.parse_and_add(to.encode('utf-8'))
        elif type(to) is tuple:
            if len(to) == 1:
                self.add_to(to[0])
            elif len(to) == 2:
                self.add_to(to[0])
                self.add_to_name(to[1])
        elif hasattr(to, '__iter__'):
            for email in to:
                self.add_to(email)

    def add_to_name(self, to_name):
        if isinstance(to_name, str):
            self.to_name.append(to_name)
        elif sys.version_info < (3, 0) and isinstance(to_name, unicode):
            self.to_name.append(to_name.encode('utf-8'))
        elif hasattr(to_name, '__iter__'):
            for tn in to_name:
                self.add_to_name(tn)

    def add_cc(self, cc):
        if isinstance(cc, str):
            email = rfc822.parseaddr(cc.replace(',', ''))[1]
            self.cc.append(email)
        elif sys.version_info < (3, 0) and isinstance(cc, unicode):
            email = rfc822.parseaddr(cc.replace(',', ''))[1].encode('utf-8')
            self.cc.append(email)
        elif hasattr(cc, '__iter__'):
            for email in cc:
                self.add_cc(email)

    def set_from(self, from_email):
        name, email = rfc822.parseaddr(from_email.replace(',', ''))
        if email:
            self.from_email = email
        if name:
            self.set_from_name(name)

    def set_from_name(self, from_name):
        self.from_name = from_name

    def set_subject(self, subject):
        self.subject = subject

    def set_text(self, text):
        self.text = text

    def set_html(self, html):
        self.html = html

    def add_bcc(self, bcc):
        if isinstance(bcc, str):
            email = rfc822.parseaddr(bcc.replace(',', ''))[1]
            self.bcc.append(email)
        elif sys.version_info < (3, 0) and isinstance(bcc, unicode):
            email = rfc822.parseaddr(bcc.replace(',', ''))[1].encode('utf-8')
            self.bcc.append(email)
        elif hasattr(bcc, '__iter__'):
            for email in bcc:
                self.add_bcc(email)

    def set_replyto(self, replyto):
        self.reply_to = replyto

    def add_attachment(self, name, file_):
        if sys.version_info < (3, 0) and isinstance(name, unicode):
            name = name.encode('utf-8')
        if isinstance(file_, str):  # filepath
            with open(file_, 'rb') as f:
                self.files[name] = f.read()
        elif hasattr(file_, 'read'):
            self.files[name] = file_.read()

    def add_attachment_stream(self, name, string):
        if sys.version_info < (3, 0) and isinstance(name, unicode):
            name = name.encode('utf-8')
        if isinstance(string, io.BytesIO):
            self.files[name] = string.read()
        else:
            self.files[name] = string

    def add_content_id(self, cid, value):
        self.content[cid] = value

    def set_headers(self, headers):
        if isinstance(headers, str):
            self.headers = headers
        else:
            self.headers = json.dumps(headers)

    def set_date(self, date):
        self.date = date

    # SMTPAPI Wrapper methods

    def add_substitution(self, key, value):
        self.smtpapi.add_substitution(key, value)

    def set_substitutions(self, subs):
        self.smtpapi.set_substitutions(subs)

    def add_unique_arg(self, key, value):
        self.smtpapi.add_unique_arg(key, value)

    def set_unique_args(self, args):
        self.smtpapi.set_unique_args(args)

    def add_category(self, cat):
        self.smtpapi.add_category(cat)

    def set_categories(self, cats):
        self.smtpapi.set_categories(cats)

    def add_section(self, key, value):
        self.smtpapi.add_section(key, value)

    def set_sections(self, sections):
        self.smtpapi.set_sections(sections)

    def add_filter(self, filterKey, setting, value):
        self.smtpapi.add_filter(filterKey, setting, value)

    def set_asm_group_id(self, value):
        self.smtpapi.set_asm_group_id(value)

    def json_string(self):
        return self.smtpapi.json_string()

