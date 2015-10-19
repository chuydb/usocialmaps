from wtforms import fields
from wtforms import Form
from wtforms import validators
from bp_includes.lib import utils
from webapp2_extras.i18n import lazy_gettext as _
from webapp2_extras.i18n import ngettext, gettext

FIELD_MAXLENGTH = 50 # intended to stop maliciously long input

# ==== Base ====

class FormTranslations(object):
    def gettext(self, string):
        return gettext(string)

    def ngettext(self, singular, plural, n):
        return ngettext(singular, plural, n)

class BaseForm(Form):
    def __init__(self, request_handler):
        super(BaseForm, self).__init__(request_handler.request.POST)

    def _get_translations(self):
        return FormTranslations()

# ==== Mixins ====
class PasswordMixin(BaseForm):
    password = fields.TextField(_('Password'), [validators.Required(),
                                                validators.Length(max=FIELD_MAXLENGTH, message=_(
                                                    "Field cannot be longer than %(max)d characters."))])

class PasswordConfirmMixin(BaseForm):
    password = fields.TextField(_('Password'), [validators.Required(),
                                                validators.Length(max=FIELD_MAXLENGTH, message=_(
                                                    "Field cannot be longer than %(max)d characters."))])
    c_password = fields.TextField(_('Confirm Password'),
                                  [validators.Required(), validators.EqualTo('password', _('Passwords must match.')),
                                   validators.Length(max=FIELD_MAXLENGTH,
                                                     message=_("Field cannot be longer than %(max)d characters."))])

class UsernameMixin(BaseForm):
    username = fields.TextField(_('Username'), [validators.Required(),
                                                validators.Length(max=FIELD_MAXLENGTH, message=_(
                                                    "Field cannot be longer than %(max)d characters.")),
                                                validators.regexp(utils.VALID_USERNAME_REGEXP, message=_(
                                                    "Username invalid. Use only letters and numbers."))])

class NameMixin(BaseForm):
    name = fields.TextField(_('Name'), [validators.Required(),
        validators.Length(max=FIELD_MAXLENGTH, message=_("Field cannot be longer than %(max)d characters."))])
    last_name = fields.TextField(_('Last Name'), [
        validators.Length(max=FIELD_MAXLENGTH, message=_("Field cannot be longer than %(max)d characters."))])    
    pass

class EmailMixin(BaseForm):
    email = fields.TextField(_('Email'), [validators.Required(),
                                          validators.Length(min=8, max=FIELD_MAXLENGTH, message=_(
                                                    "Field must be between %(min)d and %(max)d characters long.")),
                                          validators.regexp(utils.EMAIL_REGEXP, message=_('Invalid email address.'))])

class RegisterForm(PasswordMixin, NameMixin, EmailMixin):
    pass

class PasswordResetCompleteForm(PasswordConfirmMixin):
    pass

# ==== Forms ====


class EditPasswordForm(PasswordConfirmMixin):
    current_password = fields.TextField(_('Password'), [validators.Required(),
                                                        validators.Length(max=FIELD_MAXLENGTH, message=_(
                                                            "Field cannot be longer than %(max)d characters."))])
    pass

class EditEmailForm(BaseForm):
    new_email = fields.TextField(_('Email'), [validators.Required(),
                                              validators.Length(min=8, max=FIELD_MAXLENGTH, message=_(
                                                    "Field must be between %(min)d and %(max)d characters long.")),
                                              validators.regexp(utils.EMAIL_REGEXP,
                                                                message=_('Invalid email address.'))])
    password = fields.TextField(_('Password'), [validators.Required(),
                                                validators.Length(max=FIELD_MAXLENGTH, message=_(
                                                    "Field cannot be longer than %(max)d characters."))])
    pass

class LoginForm(EmailMixin):
    password = fields.TextField(_('Password'), [validators.Required(),
                                                validators.Length(max=FIELD_MAXLENGTH, message=_(
                                                    "Field cannot be longer than %(max)d characters."))], id='l_password')
    pass

class DeleteAccountForm(BaseForm):
    password = fields.TextField(_('Password'), [validators.Required(),
                                                validators.Length(max=FIELD_MAXLENGTH, message=_(
                                                    "Field cannot be longer than %(max)d characters."))], id='l_password')
    pass

class ContactForm(EmailMixin):
    name = fields.TextField(_('Name'))
    message = fields.TextAreaField(_('Message'), [validators.Required(), validators.Length(max=65536)])
    pass  

class AddressForm(BaseForm):
    zipcode = fields.TextField(_('Zipcode'), [validators.Required(), 
                                      validators.regexp(utils.ZIPCODE_REGEXP, message=_('Invalid zipcode.'))])    
    ageb = fields.TextField(_('Ageb'), [validators.Required(), 
                                      validators.regexp(utils.AGEB_REGEXP, message=_('Invalid ageb.'))])       
    latlng = fields.TextField(_('Latlng'), [validators.Length(min=1, message=_(
                                                    "Field must be at least %(min)d characters long."))])
    neighborhood = fields.TextField(_('Neighborhood'), [validators.Required(), 
                                                        validators.Length(min=1, message=_(
                                                    "Field must be at least %(min)d characters long."))])
    municipality = fields.TextField(_('Municipality'), [validators.Length(min=1, message=_(
                                                    "Field must be at least %(min)d characters long."))])
    state = fields.TextField(_('State'), [validators.Length(min=1, message=_(
                                                    "Field must be at least %(min)d characters long."))])
    region = fields.TextField(_('Region'), [validators.Length(min=1, message=_(
                                                    "Field must be at least %(min)d characters long."))])

    country = fields.SelectField(_('Country'), choices=[])
    tz = fields.SelectField(_('Timezone'), choices=[])
    pass

class SettingsProfileForm(NameMixin):
    phone = fields.TextField(_('Phone'))
    gender = fields.TextField(_('Gender'))
    birth = fields.TextField(_('Birth'))
    picture = fields.FileField(_('Picture'))
    pass

class ReferralsForm(BaseForm):
    emails = fields.TextField(_('Emails'), [validators.Required()])
    pass

