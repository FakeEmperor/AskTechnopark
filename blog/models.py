"""
Definition of models.
"""
# vendor
import django
import django.db
import datetime
import django
import django.db.models
import enum
from django.core.urlresolvers import reverse
from django.db import models
from django.contrib.sessions.base_session import AbstractBaseSession, BaseSessionManager
from django.db.models import Manager, F, Q
from django.db.models.query import QuerySet
from django.contrib.sites.models import Site
import django.contrib.auth.models
from django.utils import timezone,timesince
from django.core.exceptions import PermissionDenied
# internal
import penguin.utils.security
import penguin.utils.database
import penguin.utils.rand
import penguin.utils as utils
from api.common import AccessRights
import base64


def now():
    return timezone.now()


SALT_LEN = 64
def make_random_salt():
    return utils.rand.getrandhex(SALT_LEN)


class CaseInsensitiveQuerySet(QuerySet):
    names = None

    def __init__(self, names = None, model = None, query = None, using = None, hints = None):
        self.names = names
    
    def _filter_or_exclude(self, mapper, *args, **kwargs):
        # 'name' is a field in your Model whose lookups you want case-insensitive by default
        if self.names is not None:
            for name in self.names:
                if name in kwargs:
                    kwargs[name+'__iexact'] = kwargs[name]
                    del kwargs[name]
        return super(CaseInsensitiveQuerySet, self)._filter_or_exclude(mapper, *args, **kwargs)


# custom manager that overrides the initial query set
class CaseInsensitiveObjectManager(Manager):
    insensitive_names = None

    def __init__(self, insensitive_names=None,*args, **kwargs):
        self.insensitive_names = insensitive_names
        super(Manager, self).__init__()

    def get_query_set(self):
        return CaseInsensitiveQuerySet(self.insensitive_names, self.model)

# Create your models here.
class IntegerRangeField(models.IntegerField):
    def __init__(self, verbose_name=None, name=None, min_value=None, max_value=None, **kwargs):
        self.min_value, self.max_value = min_value, max_value
        models.IntegerField.__init__(self, verbose_name, name, **kwargs)

    def formfield(self, **kwargs):
        defaults = {'min_value': self.min_value, 'max_value':self.max_value}
        defaults.update(kwargs)
        return super(IntegerRangeField, self).formfield(**defaults)


# НЕМНОГО О СТИЛЕ НАИМЕНОВАНИЯ ЧЛЕНОВ БД
# link_*         - данное поле - ссылка на объект (o2o, m2o, o2m, m2m)
# native_*_id    - данное поле - нативная ссылка на объект (по id)
# temp_*         - данное поле - временное поле (которое иногда не требуется)
# calc_*         - данное поле - вычислимое поле (кэшируемое значение)


class User_ConfirmationType(enum.IntEnum):
    UCT_MIN                     = 0
    
    UCT_NONE                    = 0
    UCT_REGISTRATION_CONFIRM    = 1
    UCT_PASSWORD_RESET_CONFIRM  = 2
    
    UCT_MAX                     = 2


class App(models.Model):
    name            =   models.CharField(max_length=60, unique=True)
    salt            =   models.CharField(max_length=256)
    date_created    =   models.DateTimeField(default=timezone.now)

    @staticmethod
    def CreateApp(name, date=None, save=True):
        if date is None:
            a = App(name=name, salt=penguin.utils.rand.getrandhex(256))
        else:
            a = App(name=name, salt=penguin.utils.rand.getrandhex(256), date_created=date)
        if save:
            a.save()
        return a


class UserManager(django.contrib.auth.models.BaseUserManager):
    def create_user(self, username, email, first_name = None, last_name = None, password=None, save = True):
        """ Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')
        if not username:
            raise ValueError('Users must have a username')

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            first_name=first_name,
            last_name=last_name,
            access_scope=AccessRights.AR_PREDEFINED_User
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username,email, first_name = None, last_name = None, password = None ):
        """ Creates and saves a superuser with the given email, date of
        birth and password.
        """
        if not password:
            raise ValueError("Superusers must have a password, and a strong one, I shall say!")

        user = self.create_user(username, email,
                                password=password,
                                first_name=first_name,
                                last_name=last_name,
                                save=False
                                )
        user.access_scope = AccessRights.AR_PREDEFINED_God
        user.save(using=self._db)
        return user


MAX_USERNAME_LEN = 30
MAX_FIRST_LAST_NAME_LEN = 40
class User(django.contrib.auth.models.AbstractBaseUser):
    # 7 days for link live
    CONFIRMATION_LINK_TTL   =   7*24*3600
    
    # core
    username        =   models.CharField(max_length=MAX_USERNAME_LEN, db_index=True, unique=True)
    email           =   models.EmailField(unique=True, db_index=True)
    access_scope    =   models.PositiveIntegerField(default=AccessRights.AR_PREDEFINED_AnonimUser)
    # personal
    first_name      =   models.CharField(max_length=MAX_FIRST_LAST_NAME_LEN, blank=True, null=True)
    last_name       =   models.CharField(max_length=MAX_FIRST_LAST_NAME_LEN, blank=True, null=True)
    # auth
    # password        =   models.BinaryField(max_length = 512) # hash of the password+salt
    salt            =   models.CharField(max_length=SALT_LEN, default=make_random_salt)
    is_active       =   models.BooleanField(default=True) # also, inherited from AbstractBaseUser
    # temporary
    temp_confirmation_code  = models.CharField(max_length=255, null=True, blank=True)
    temp_confirmation_type  = IntegerRangeField(min_value=User_ConfirmationType.UCT_MIN,
                                                max_value=User_ConfirmationType.UCT_MAX,
                                                null=True, blank=True)
    temp_confirmation_date  = models.DateTimeField(null=True, blank=True)
    # customizations
    pic                 =   models.ImageField(upload_to="/media/user/", null=True, blank=True)
    # stats
    registration_date   =   models.DateTimeField(default=timezone.now)

    calc_rating         =   models.PositiveIntegerField(default = 0)
    calc_posts          =   models.PositiveIntegerField(default = 0)
    calc_comments       =   models.PositiveIntegerField(default = 0)
    # overrides default
    objects         =   CaseInsensitiveObjectManager(["username", "email"])
    # stats and links
    link_vote_users = models.ManyToManyField('self', symmetrical = False)
    
    link_vote_posts = models.ManyToManyField('Post')  # using string name because Post defined after this class 
    link_vote_comments = models.ManyToManyField('Comment') # ^ same

    ############## OVERRIDE DEFAULT USER MANAGER ###################
    
    objects = UserManager()

    ############ OVERRIDES OF ABSTRACT BASE USER MODEL ##############
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def is_anonymous(self):
        """<@default: Always returns False.
        This is a way of differentiating from AnonymousUser objects.
        Generally, you should prefer using is_authenticated() to this method.>
        """
        return self.access_scope == AccessRights.AR_PREDEFINED_AnonimUser

    def get_full_name(self):
        # The user is identified by their email address
        return self.email

    def get_short_name(self):
        # The user is identified by their email address
        return self.username

    def __str__(self):
        return '[ blog.User object: username={0}, email={1}, access_rights={2} ]'.format(self.username,self.email,self.access_scope)

    # TODO: Change this method to make use of AccessRights
    def has_perm(self, perm, obj=None):
        """ Does the user have a specific permission?"""
        # Simplest possible answer: Yes, always
        return True

    # TODO: Change this method to make use of AccessRights
    def has_module_perms(self, app_label):
        """ Does the user have permissions to view the app `app_label`?"""
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        """ Is the user a member of staff?"""
        # Simplest possible answer: god is an admin :)
        return self.access_scope == AccessRights.AR_PREDEFINED_God

    def set_password(self, raw_password):
        """ Sets the user’s password to the given raw string, 
        taking care of the password hashing.
        Doesn’t save the AbstractBaseUser object.
        When the raw_password is None, 
        the password will be set to an unusable password,
        as if set_unusable_password() were used.
        """
        self.password = penguin.utils.security.get_hash(raw_password)

    def check_password(self, raw_password):
        """ Returns True if the given raw string is the correct password for the user.
        (This takes care of the password hashing in making the comparison.)
        """
        return self.password == penguin.utils.security.get_hash(raw_password)

    ########################################################################
    @classmethod
    def CreateUser(cls, uname:str, password:str, email:str, salt = None,
                   access_scope: AccessRights = AccessRights.AR_PREDEFINED_NONE, registration_date = None,
                   first_name = None, last_name = None, pic = None, save = True):
        """ Tries to create user with definite password hash, email, access scope, reg date, and username
        @return created user object
        """
        if not salt:
            salt = make_random_salt()
        if registration_date is None: registration_date = timezone.now()
        u = cls(username=uname, password=password, email=email, salt=salt, access_scope=access_scope,
                registration_date=registration_date, first_name=first_name, last_name=last_name)
        # TODO: make pic
        if pic:
            raise NotImplementedError("picture support not implemented yet")
        if save:
            u.save()
        return u


    def MakeUserHash(self,value):
        return utils.security.get_hash(value + self.salt)

    
    def Set(self, username = None, password = None, email = None, save = False):
        """ Method modifies user fields
        @return User object (self) if operation finished successfully
                throws any other error if something happened (prepare yourself!)
        """
        if username is not None:
            self.username = username
        if password is not None:
            self.password = password
        if email is not None:
            self.email = email
        if save:
            self.save()
        return self

    def SetPicture(self, pic_url: str):

        raise NotImplementedError("SetPicture method is not yet implemented")

    def MakeConfirmationCode(self, type: int, date = None, force = False):
        """ Generates new confirmation code
        """
        # if confirmation type present and not None, and date is not stale, and force param is False - raise exception
        if not force and self.temp_confirmation_type is not None and self.temp_confirmation_type != User_ConfirmationType.UCT_NONE \
            and self.temp_confirmation_date + timezone.timedelta(seconds=User.CONFIRMATION_LINK_TTL) >= timezone.now():
            raise PermissionError("Another confirmation activity in progress. Use 'force' parameter to override this check")
        self.temp_confirmation_type = type
        self.temp_confirmation_date = date if date is not None else timezone.now()
        self.temp_confirmation_code = utils.security.get_hash(utils.rand.getrandhex(40) + str(self.pk))

        return self.temp_confirmation_code



    @staticmethod
    def MakeConfirmationLink(uid, type:int, code: str):
        current_site = Site.objects.get_current()
        if type == User_ConfirmationType.UCT_REGISTRATION_CONFIRM:
            req = reverse("api.user.confirm_registration", current_app="api")
        elif type == User_ConfirmationType.UCT_PASSWORD_RESET_CONFIRM:
            req = reverse("forgot_password", current_app="blog")
        else:
            raise ValueError("Invalid type")
        assert isinstance(current_site, Site)
        # external link bit + domain name + link to confirm
        return "//" + current_site.domain + req + "?uid={0}&code={1}"\
            .format(uid, code)

    def _stop_confirm(self, save=True, also_save: tuple = ()):
        """
        Stops confirmation process.
        Resets temp_confirmation_type, temp_confirmation_date, temp_confirmation_code fields
        """
        self.temp_confirmation_type = User_ConfirmationType.UCT_NONE
        self.temp_confirmation_date = None
        self.temp_confirmation_code = None
        if save:
            self.save(update_fields=('temp_confirmation_type', 'temp_confirmation_code', 'temp_confirmation_date') +
                                    ( () if also_save is None else also_save ))

    def _check_code(self, code):
        # check code
        if self.temp_confirmation_code != code:
            raise ValueError("Confirmation code mismatch")
        # check date
        if self.temp_confirmation_date + datetime.timedelta(seconds=self.CONFIRMATION_LINK_TTL) < timezone.now():
            # reset also
            self._stop_confirm()
            raise TimeoutError("Confirmation code is stale")

    def EndConfirmRegistration(self, code):
        """
        Ends registration confirmation
        :param code: Confirmation code from link
        :return: Returns True, if confirmation code matches one in db and code isn't stale.
        :raises: TimeoutError, if confirmation code is stale
            ValueError, if confirmation code is wrong
        """
        if self.temp_confirmation_type == User_ConfirmationType.UCT_REGISTRATION_CONFIRM:\
            self._check_code(code)
        else:
            raise TypeError("Other confirmation action in progress")
        # ok?
        # update rights
        self.access_scope = F('access_scope').bitor(AccessRights.AR_PREDEFINED_User)
        self._stop_confirm(also_save=('access_scope',))
        return True

    def BeginConfirmRegistration(self):
        code = self.MakeConfirmationCode(User_ConfirmationType.UCT_REGISTRATION_CONFIRM)
        link = User.MakeConfirmationLink(self.pk, User_ConfirmationType.UCT_REGISTRATION_CONFIRM, code)
        return link

    def EndResetPassword(self, code, new_password_hash):
        """
        Ends password reset process
        :param code: Confirmation code from link
        :param new_password_hash: Hash of the new password
        :return: Returns True, if password is reset
        :raises: TimeoutError, if confirmation code is stale
        """
        self._check_code(code)
        # ok? change password and invalidate sessions
        self.password = new_password_hash
        Session.InvalidateSessionsForUser(self)
        self._stop_confirm(also_save=['password'])
        return True

    # TODO: Merge it with BeginConfirmRegistration()
    def BeginResetPassword(self):
        code = self.MakeConfirmationCode(User_ConfirmationType.UCT_PASSWORD_RESET_CONFIRM)
        link = User.MakeConfirmationLink(self.pk, User_ConfirmationType.UCT_PASSWORD_RESET_CONFIRM, code)
        return link


############    SESSION     #############


class Session(AbstractBaseSession ):
    access_scope    =   models.PositiveIntegerField(null=True)
    userid          =   models.PositiveIntegerField(null=True)

    @classmethod
    def GenerateForUser(cls, user, scope=AccessRights.AR_PREDEFINED_God, strict_security=False):
        """
        Generates new session for user and registeres it in db
        @param scope            Defines access_scope for the session. Efficent scope cannot hold
            more rights than of user's. To temporary elevate User in rights, use another approach.
        @param strict_security  Raises PermissionDenied if requested scope is broader, than User's
            possible scope.
        """
        assert isinstance(user, User)
        # check permissions
        effective_scope = AccessRights.AR_PREDEFINED_NONE
        if strict_security:
            # check strictly
            diff_scope = scope ^ user.access_scope
            if diff_scope != diff_scope & user.access_scope:
                raise PermissionError("Requested session scope higher than user's possible scope")
            effective_scope = scope
        else:
            effective_scope = scope & user.access_scope

        sess = cls(access_scope=effective_scope, session_key=penguin.utils.rand.getrandhex(40), userid=user)
        return sess

    @classmethod
    def InvalidateSessionsForUser(cls, user):
        assert isinstance(user, User)
        user.session_set.delete()

    def Invalidate(self):
        """
        Removes session from db
        """
        self.delete()

    #@classmethod
    #def IsValid(cls, user, token:str):
    #    assert isinstance(user, User)
    #    sset = user.session_set
    #    assert isinstance(sset, models.QuerySet)
    #    sset = sset.filter('session_key')
    #    sset = list(sset)
    #    token = token.lower()
    #    for s in sset:
    #        assert isinstance(s, Session)
    #        if s.__create_token(user) == token:
    #            return True
    #    return False

    def __create_token(self, user):
        assert isinstance(user, User)
        return penguin.utils.security.get_hash(self.session_key + user.salt)

    @property
    def CookieToken(self):
        return self.__create_token(User.objects.only("salt").get(pk=self.userid))

    def HasAccess(self, action, data=None):
        scope = self.access_scope
        if scope == AccessRights.AR_PREDEFINED_God:
            return True
        needed_scope = AccessRights.ResolveRightsScopeFromAction(action, data=data)
        # Check if we perform operations on user himself
        if needed_scope | AccessRights.AR_SCOPE_COLLECTIONS_PrivateUser != 0 and \
           isinstance(data, User) and data.pk == self.userid:
            # if at least one read user permission is set - set all read permissions
            if scope & AccessRights.AR_SCOPE_COLLECTIONS_ReadUserAny:
                scope |= AccessRights.AR_SCOPE_COLLECTIONS_ReadUserAny
            # if at least one write perrmission is set - set all write permission
            if scope & AccessRights.AR_SCOPE_COLLECTIONS_WriteUserAny:
                scope |= AccessRights.AR_SCOPE_COLLECTIONS_WriteUserAny
        return needed_scope & scope == needed_scope



############      TAG       #############


class Tag(models.Model):
    primary_name = models.CharField(max_length=50)
    
    calc_total_posts    = models.PositiveIntegerField(blank=True, default=0)
    calc_total_rating   = models.PositiveIntegerField(blank=True, default=0, db_index=True)



##############          POST        ##########


class PostType(enum.IntEnum):
    QUESTION =   0
    ANSWER   =   1

class Post(models.Model):

    # actually unique
    url                 =   models.CharField(max_length=256, db_index=True)

    link_tags           =   models.ManyToManyField(Tag)
    link_parent_post    =   models.ForeignKey('self', models.CASCADE, null=True)
    link_user           =   models.ForeignKey(User, models.SET_NULL, null=True)
    
    text                =   models.TextField()
    title               =   models.CharField(max_length=256)
    type                =   IntegerRangeField(max_value=1, min_value=0)
    date                =   models.DateTimeField()

    pic                 =   models.ImageField(upload_to="/uploads/")

    calc_rating         =   models.PositiveIntegerField(null=True, blank=True)
    calc_comments       =   models.PositiveIntegerField(null=True, blank=True)
    calc_linked_posts   =   models.PositiveIntegerField(null=True, blank=True)


    @classmethod
    def UrlFromHeader(cls, header:str, id: int):
        import re, string; 
        import unidecode
        url = ""
        hd = header.strip()
        hd = hd[:min(245,len(hd))].replace(' ','_')
        pattern = re.compile('[\W]+')
        
        hd = unidecode.unidecode(hd).lower()
        hd = pattern.sub('', hd)
        url = hd + '_' + str(id)
        return url

    def Publicize(self):
        self.url = self.UrlFromHeader(self.title,self.pk)
        self.save(update_fields=('url',))

    @classmethod
    def CreatePost(cls, type: int, author: User, title: str, text: str, pic=None, date: datetime.datetime=None,
                   tags=None, parent_post=None, save=True, publicize=True):
        if date is None:
            date = timezone.now()
        post = cls(type=type, date=date, text=text, link_user=author, pic=pic,
                   title=title)
        if parent_post:
            post.link_parent_post = parent_post
        if save or publicize:
            post.save()
        if publicize:
            post.Publicize()
        return post

    def dump(self, *fields):
        return {'id': self.pk, 'title': str(self.title),
                'text': str(self.text), 'date': str(self.date),
                'url': self.url,
                'parent_post': self.link_parent_post_id,
                'type': PostType(self.type)._name_.lower(),
                'author': self.link_user_id}



##############          COMMENT        ##########
class Comment(models.Model):

    link_parent_post    =   models.ForeignKey(Post)
    link_user           =   models.ForeignKey(User)

    text                =   models.TextField()

    chain_parent        =   models.ForeignKey("self")
