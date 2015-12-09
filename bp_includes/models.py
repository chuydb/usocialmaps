from webapp2_extras.appengine.auth.models import User
from google.appengine.ext import ndb, blobstore
import datetime

#--------------------------------------- USER MODEL PROPERTIES  -----------------------------------------------------------         
class Rewards(ndb.Model):
    amount = ndb.IntegerProperty()                                                                  #: number of points acquired 
    earned = ndb.BooleanProperty()                                                                  #: to identify if earned or spent
    category = ndb.StringProperty(choices = ['invite','donation','purchase','configuration'])       #: to identify main reason of rewards attribution
    content = ndb.StringProperty()                                                                  #: used to track referred emails
    timestamp = ndb.StringProperty()                                                                #: when was it assigned
    status = ndb.StringProperty(choices = ['invited','joined','completed','inelegible'])            #: current status of reward

class Address(ndb.Model):
    address_from_coord = ndb.GeoPtProperty()                                                        #: lat/long address
    address_from = ndb.StringProperty()                                                             #: text address
    
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

    def get_image_url(self):
        if self.picture:
            return "http://usocialmaps.appspot.com/media/serve/profile/%s/" % self._key.id()
        else:
            return -1
#--------------------------------------- ENDOF   U S E R    M O D E L -----------------------------------------------------          

class Report(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add = True)                                                                             #: Creation date on ndb
    updated = ndb.DateTimeProperty(auto_now = True)                                                                                 #: Modification date on ndb
    title = ndb.StringProperty()                                                                                                    #: Report title
    description = ndb.TextProperty()                                                                                                #: Report description
    address_from_coord = ndb.GeoPtProperty()                                                                                        #: lat/long address for report 
    address_from = ndb.StringProperty()                                                                                             #: text address for report
    cdb_id = ndb.IntegerProperty(default = -1)                                                                                      #: ID in CartoDB PostGIS DB
    user_id = ndb.IntegerProperty(required = True, default = -1)                                                                    #: Reporting user ID
    image_url = ndb.StringProperty()                                                                                                #: Report media 
    likeability = ndb.StringProperty()                                                                                              #: Parent category
    feeling  = ndb.StringProperty()                                                                                                 #: Child category
    follows = ndb.IntegerProperty(default = 0)                                                                                      #: Followers as votes/relevance for this report
    via = ndb.StringProperty(choices = ['web','whatsapp','phone','street','networks','office','event','letter'], default = 'web')   #: Report via
    
    def get_id(self):
        return self._key.id()

    def get_user_email(self):
        user = User.get_by_id(long(self.user_id)) if self.user_id != -1 else None
        if user:
            return user.email
        else:
            return ''

    def get_user_name(self):
        user = User.get_by_id(long(self.user_id)) if self.user_id != -1 else None
        if user:
            return user.name
        else:
            return ''

    def get_user_lastname(self):
        user = User.get_by_id(long(self.user_id)) if self.user_id != -1 else None
        if user:
            return user.last_name
        else:
            return ''

    def get_user_address(self):
        user = User.get_by_id(long(self.user_id)) if self.user_id != -1 else None
        if user:
            if user.address:
                return user.address.address_from
        else:
            return ''

    def get_user_phone(self):
        user = User.get_by_id(long(self.user_id)) if self.user_id != -1 else None
        if user:
            return user.phone
        else:
            return ''

    def get_human_date(self):
        d1 = datetime.datetime(self.created.year,self.created.month,self.created.day)
        d2 = datetime.datetime(datetime.date.today().year,datetime.date.today().month,datetime.date.today().day)
        diff = (d2-d1).days
        return str(diff) + " days ago"

    def get_formatted_date(self):
        return datetime.datetime(self.created.year,self.created.month,self.created.day).strftime("%Y-%m-%d")

    def get_log_count(self):
        logs = Comments.query(Comments.report_id == self._key.id())
        return logs.count()

    def get_last_log(self):
        logs = Comments.query(Comments.report_id == int(self._key.id()))
        logs = logs.order(-Comments.created)
        for log in logs:
            return log.user_email
            break
        return '---'

    def get_color(self):
        if self.likeability == 'Not at all':
            return 'FD5D47'
        if self.likeability == 'A little':
            return 'FFAA1E'
        if self.likeability == 'As any other':
            return 'F3CA59'
        if self.likeability == 'A lot':
            return 'B3DA93'
        if self.likeability == 'I love it':
            return '66D7E6'
        return '9e9e9e'

    @classmethod
    def get_by_cdb(cls, cdb_id):
        return cls.query(cls.cdb_id == cdb_id).get()

class Comments(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)                                               
    user_email = ndb.StringProperty(required = True)
    report_id = ndb.IntegerProperty(required = True)
    contents = ndb.TextProperty(required = True)

    def get_user(self):
        user = User.get_by_email(self.user_email)
        if user:
            return user
        else:
            return None

    def get_report(self):
        report = Report.get_by_id(long(self.report_id))
        if report:
            return report
        else:
            return None

    def get_formatted_date(self):
        return datetime.datetime(self.created.year,self.created.month,self.created.day, self.created.hour, self.created.minute, self.created.second).strftime("%Y-%m-%d at %X (GMT-00)")

class Followers(ndb.Model):
    user_id = ndb.IntegerProperty(required = True)
    report_id = ndb.IntegerProperty(required = True)

    @classmethod
    def get_user_follows(cls, user_id):
        return cls.query(cls.user_id == user_id)

    @classmethod
    def get_report_follows(cls, report_id):
        return cls.query(cls.report_id == report_id)


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
