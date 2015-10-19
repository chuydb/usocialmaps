from webapp2_extras.appengine.auth.models import User
from google.appengine.ext import ndb, blobstore

#--------------------------------------- USER MODEL PROPERTIES  -----------------------------------------------------------         
class Rewards(ndb.Model):
    amount = ndb.IntegerProperty()                                                                  #: number of points acquired 
    earned = ndb.BooleanProperty()                                                                  #: to identify if earned or spent
    category = ndb.StringProperty(choices = ['invite','donation','purchase','configuration'])       #: to identify main reason of rewards attribution
    content = ndb.StringProperty()                                                                  #: used to track referred emails
    timestamp = ndb.StringProperty()                                                                #: when was it assigned
    status = ndb.StringProperty(choices = ['invited','joined','completed','inelegible'])            #: current status of reward

class Notifications(ndb.Model):  
    sms = ndb.BooleanProperty()
    email = ndb.BooleanProperty()
    endpoint = ndb.BooleanProperty()
    twitter = ndb.StringProperty()

class Address(ndb.Model):
    ageb = ndb.StringProperty()                                                                     #: Mexico Only - INEGI zone key 
    region = ndb.StringProperty()                                                                   #: Mexico Only - CFE related region
    country = ndb.StringProperty()                                                                  #: User Country, initialized by boilerplate... 
    state = ndb.StringProperty()                                                                    #: Administrative state region
    municipality = ndb.StringProperty()                                                             #: Administrative municipality region   
    zipcode = ndb.IntegerProperty()                                                                 #: Administrative zipcode region
    neighborhood = ndb.StringProperty()                                                             #: Administrative neighborhood region
    latlng = ndb.GeoPtProperty()                                                                    #: Geocoded lat,lng, from address fields
    #street = ndb.StringProperty()                                                                  #: Unused
    #streetnum = ndb.StringProperty()                                                               #: Unused
    tz = ndb.StringProperty()                                                                       #: User TimeZone, initialized by boilerplate...       
    
class Media(ndb.Model):
    blob_key = ndb.BlobKeyProperty()                                                                #: Refer to https://cloud.google.com/appengine/docs/python/blobstore/

class BlogPost(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)                                               #: Creation date.
    updated = ndb.DateTimeProperty(auto_now=True)                                                   #: Modification date.    
    blob_key = ndb.BlobKeyProperty()                                                                #: Refer to https://cloud.google.com/appengine/docs/python/blobstore/
    title = ndb.StringProperty(required = True)
    subtitle = ndb.StringProperty(indexed = False)
    author = ndb.StringProperty()
    brief = ndb.TextProperty(required = True, indexed = False)
    content = ndb.TextProperty(required = True, indexed = False)
    category = ndb.StringProperty(repeated = True)

    def get_id(self):
        return self._key.id()
#--------------------------------------- U S E R    M O D E L -----------------------------------------------------          
class User(User):
    """
    Universal user model. Can be used with App Engine's default users API,
    own auth or third party authentication methods (OpenID, OAuth etc).
    """
    created = ndb.DateTimeProperty(auto_now_add=True)                                              #: Creation date.
    updated = ndb.DateTimeProperty(auto_now=True)                                                  #: Modification date.    
    last_login = ndb.StringProperty()                                                              #: Last user login.    
    username = ndb.StringProperty()                                                                #: User defined unique name, also used as key_name. >>Replaced as an email duplicate to avoid same emails several accounts
    name = ndb.StringProperty()                                                                    #: User Name    
    last_name = ndb.StringProperty()                                                               #: User Last Name    
    email = ndb.StringProperty()                                                                   #: User email
    phone = ndb.StringProperty()                                                                   #: User phone
    twitter_handle = ndb.StringProperty()                                                          #: User twitter handle for notification purposes
    address = ndb.StructuredProperty(Address)                                                      #: User georeference
    password = ndb.StringProperty()                                                                #: Hashed password. Only set for own authentication.    
    birth = ndb.DateProperty()                                                                     #: User birthday.
    gender = ndb.StringProperty(choices = ['male','female'])                                       #: User sex    
    activated = ndb.BooleanProperty(default=False)                                                 #: Account activation verifies email    
    link_referral = ndb.StringProperty()                                                           #: Once verified, this link is used for referral sign ups (uses bit.ly)    
    rewards = ndb.StructuredProperty(Rewards, repeated = True)                                     #: Rewards allocation property, includes referral email tracking.    
    role = ndb.StringProperty(choices = ['NA','Member','Admin'], default = 'Admin')                #: Role in account
    notifications = ndb.StructuredProperty(Notifications)                                          #: Setup of notifications
    picture = ndb.BlobProperty()                                                                   #: User profile picture as an element in datastore of type blob
	
    @classmethod
    def get_by_email(cls, email):
        """Returns a user object based on an email.

        :param email:
            String representing the user email. Examples:

        :returns:
            A user object.
        """
        return cls.query(cls.email == email).get()

    @classmethod
    def create_resend_token(cls, user_id):
        entity = cls.token_model.create(user_id, 'resend-activation-mail')
        return entity.token

    @classmethod
    def validate_resend_token(cls, user_id, token):
        return cls.validate_token(user_id, 'resend-activation-mail', token)

    @classmethod
    def delete_resend_token(cls, user_id, token):
        cls.token_model.get_key(user_id, 'resend-activation-mail', token).delete()

    def get_social_providers_names(self):
        social_user_objects = SocialUser.get_by_user(self.key)
        result = []
        for social_user_object in social_user_objects:
            result.append(social_user_object.provider)
        return result

    def get_social_providers_info(self):
        providers = self.get_social_providers_names()
        result = {'used': [], 'unused': []}
        for k,v in SocialUser.PROVIDERS_INFO.items():
            if k in providers:
                result['used'].append(v)
            else:
                result['unused'].append(v)
        return result
#--------------------------------------- ENDOF   U S E R    M O D E L -----------------------------------------------------          


class LogVisit(ndb.Model):
    user = ndb.KeyProperty(kind=User)
    uastring = ndb.StringProperty()
    ip = ndb.StringProperty()
    timestamp = ndb.StringProperty()

class OptionsSite(ndb.Model):
    name = ndb.KeyProperty
    value = ndb.StringProperty()
    @classmethod
    def get_option(cls,option_name):
        return cls.query(name=option_name)

class LogEmail(ndb.Model):
    sender = ndb.StringProperty(required=True)
    to = ndb.StringProperty(required=True)
    subject = ndb.StringProperty(required=True)
    body = ndb.TextProperty()
    when = ndb.DateTimeProperty()

    def get_id(self):
        return self._key.id()

class SocialUser(ndb.Model):
    PROVIDERS_INFO = { # uri is for OpenID only (not OAuth)
        'google': {'name': 'google', 'label': 'Google', 'uri': 'gmail.com'},
        'github': {'name': 'github', 'label': 'Github', 'uri': ''},
        'facebook': {'name': 'facebook', 'label': 'Facebook', 'uri': ''},
        'linkedin': {'name': 'linkedin', 'label': 'LinkedIn', 'uri': ''},
        'myopenid': {'name': 'myopenid', 'label': 'MyOpenid', 'uri': 'myopenid.com'},
        'twitter': {'name': 'twitter', 'label': 'Twitter', 'uri': ''},
        'yahoo': {'name': 'yahoo', 'label': 'Yahoo!', 'uri': 'yahoo.com'},
    }

    user = ndb.KeyProperty(kind=User)
    provider = ndb.StringProperty()
    uid = ndb.StringProperty()
    extra_data = ndb.JsonProperty()

    @classmethod
    def get_by_user(cls, user):
        return cls.query(cls.user == user).fetch()

    @classmethod
    def get_by_user_and_provider(cls, user, provider):
        return cls.query(cls.user == user, cls.provider == provider).get()

    @classmethod
    def get_by_provider_and_uid(cls, provider, uid):
        return cls.query(cls.provider == provider, cls.uid == uid).get()

    @classmethod
    def check_unique_uid(cls, provider, uid):
        # pair (provider, uid) should be unique
        test_unique_provider = cls.get_by_provider_and_uid(provider, uid)
        if test_unique_provider is not None:
            return False
        else:
            return True
    
    @classmethod
    def check_unique_user(cls, provider, user):
        # pair (user, provider) should be unique
        test_unique_user = cls.get_by_user_and_provider(user, provider)
        if test_unique_user is not None:
            return False
        else:
            return True

    @classmethod
    def check_unique(cls, user, provider, uid):
        # pair (provider, uid) should be unique and pair (user, provider) should be unique
        return cls.check_unique_uid(provider, uid) and cls.check_unique_user(provider, user)
    
    @staticmethod
    def open_id_providers():
        return [k for k,v in SocialUser.PROVIDERS_INFO.items() if v['uri']]
