"""
Definition of models.
"""

from django.db import models
import asktechnopark.utils.security
import django
import django.db
import django.db.models
import enum
# Create your models here.
class IntegerRangeField(models.IntegerField):
    def __init__(self, verbose_name=None, name=None, min_value=None, max_value=None, **kwargs):
        self.min_value, self.max_value = min_value, max_value
        models.IntegerField.__init__(self, verbose_name, name, **kwargs)
    def formfield(self, **kwargs):
        defaults = {'min_value': self.min_value, 'max_value':self.max_value}
        defaults.update(kwargs)
        return super(IntegerRangeField, self).formfield(**defaults)


#НЕМНОГО О СТИЛЕ НАИМЕНОВАНИЯ ЧЛЕНОВ БД
#link_*         - данное поле - ссылка на объект (o2o, m2o, o2m, m2m)
#native_*_id    - данное поле - нативная ссылка на объект (по id)
#temp_*         - данное поле - временное поле (которое иногда не требуется)
#calc_*         - данное поле - вычислимое поле (кэшируемое значение)


class User_ConfirmationType(enum.IntEnum):
    UCT_MIN                     = 0
    
    UCT_NONE                    = 0
    UCT_REGISTRATION_CONFIRM    = 1
    UCT_PASSWORD_RESET_CONFIRM  = 2
    
    UCT_MAX                     = 2

class AccessRights(enum.IntEnum):
    """Enum that defines access fields for restricted and non-restricted areas in user activity
    AccessRights scope composed of 32-bit length int:
    |1byte|1byte|1byte|1byte|
     Admin  Mod  Write  Read
    Read:   0x01    -   Read public sections of site
            0x02    -   Read areas for authorized users of site
            0x10    -   Read public user data
            0x40    -   Read public user settings
            0x20    -   Read private user data
            0x80    -   Read private user settings
    Write:  0x01    -   Write Comments
            0x02    -   Write Posts
            0x10    -   Change public user data
            0x20    -   Change public user settings
            0x40    -   Change private user data
            0x80    -   Change private user settings

     Admin: 0x01    -   Read Object
            0x02    -   Change Object
            0x04    -   Delete Object
    """
    AR_PREDEFINED_NONE              =   0x00000000
    AR_PREDEFINED_AnonimUser        =   0x00000001
    AR_PREDEFINED_NotConfirmedUser  =   0x0000F0F3
    AR_PREDEFINED_User              =   0x0000F3F3
    AR_PREDEFINED_God               =   0xFFFFFFFF

    AR_SCOPE_Read                   =   0x000000FF
    AR_SCOPE_Write                  =   0x0000FF00
    AR_SCOPE_Mod                    =   0x00FF0000
    AR_SCOPE_Admin                  =   0xFF000000
    #READ
    AR_SCOPE_Read_PublicSite        =   0x01
    AR_SCOPE_Read_AuthSite          =   0x02

    AR_SCOPE_Read_PublicUserData    =   0x10
    AR_SCOPE_Read_PublicUserSets    =   0x20
    AR_SCOPE_Read_PrivateUserData   =   0x40
    AR_SCOPE_Read_PrivateUserSets   =   0x80
    #WRITE
    AR_SCOPE_Write_Comment          =   0x0100
    AR_SCOPE_Write_Post             =   0x0200

    AR_SCOPE_Write_PublicUserData   =   0x1000
    AR_SCOPE_Write_PublicUserSets   =   0x2000
    AR_SCOPE_Write_PrivateUserData  =   0x4000
    AR_SCOPE_Write_PrivateUserSets  =   0x8000
    #ADMIN
    AR_SCOPE_Admin_ReadObjects      =   0x01000000
    AR_SCOPE_Admin_ChangeObjects    =   0x02000000
    AR_SCOPE_Admin_DeleteObjects    =   0x04000000
    AR_SCOPE_Admin_CreateObjects    =   0x08000000

    AR_SCOPE_COLLECTIONS_PrivateUserData    = 0x40 | 0x4000
    AR_SCOPE_COLLECTIONS_PrivateUserSets    = 0x80 | 0x8000
    AR_SCOPE_COLLECTIONS_PrivateUser        = 0x40 | 0x80 | 0x4000 | 0x8000

    AR_SCOPE_COLLECTIONS_WriteUserAny          = 0xF000
    AR_SCOPE_COLLECTIONS_ReadUserAny           = 0xF0

    @classmethod
    def ResolveScopeFromAction(cls, action):
        raise NotImplementedError("Not yet implemented")




class User(models.Model):
    #persistent
    username        =   models.CharField(max_length = 30, db_index = True, unique = True)
    email           =   models.EmailField(unique = True)
    access_scope    =   models.PositiveIntegerField(default = AccessRights.AR_PREDEFINED_AnonimUser)
    anon            =   models.BooleanField(default = True)
    
    password        =   models.BinaryField(max_length = 512)
    salt            =   models.BinaryField(max_length = 32)
    
    temp_confirmation_code = models.CharField(max_length = 255)
    temp_confirmation_type = IntegerRangeField( min_value = User_ConfirmationType.UCT_MIN,
                                                max_value = User_ConfirmationType.UCT_MAX)
    
    pic                 =   models.ImageField(upload_to="/media/user/")

    #self link
    link_vote_users = models.ManyToManyField('self', symmetrical = False)
    # using string name because Post defined after this class 
    link_vote_posts = models.ManyToManyField('Post') 
    link_vote_comments = models.ManyToManyField('Comment')

    """
    Tries to create user with definite password hash
    """
    @classmethod
    def CreateUser(cls, uname:str, password:str):
        u = cls(username=uname, password=password)
        return u


    #TODO - send to middleware
    """
    Performs search on username and tries to authenticate
    with it
    @returns None or a tuple with created cookie
    """
    def Auth(username, hashed_password, session = None):
        #Find by username
        users = User.objects
        assert isinstance(users, django.db.models.QuerySet)
        try:
            user = users.get(username=username)
            assert isinstance(user, User)
            if user.password != hashed_password:
                return None
            #authenticate
            session['id'] = user._get_pk_val()
            session['anon'] = user.anon
            return user,cookie
        except django.db.models.ObjectDoesNotExist:
            return None

    @classmethod
    def GetPwdHash(cls):
        pass

    """
    Method modifies user fields
    confirm_action_password - sometimes is necessary to perform operations
    @return User object (self) if operation finished successfully
            throws SecurityError if confirm_action_password does not match
            throws any other error if something happened (prepare yourself!)
    """
    def Set(self, username = None, password = None, email = None, confirm_action_password = None):
        pass


class Session(models.Model):
    access_scope    =   models.PositiveIntegerField()
    access_key      =   models.BinaryField(max_length = 64)
    link_user       =   models.ForeignKey(User, models.CASCADE)

    def HasAccess(self, action, token_scope, data = None):
        if token_scope == AccessRights.AR_PREDEFINED_God:
            return True
        needed_scope = AccessRights.ResolveScopeFromAction(action)
        #Check if we perform operations on user himself
        if needed_scope | AccessRights.AR_SCOPE_COLLECTIONS_PrivateUser != 0 and \
           isinstance(data,User) and data == link_user:
            #if at least one read user permission is set
            if token_scope & AccessRights.AR_SCOPE_COLLECTIONS_ReadUserAny:
                token_scope |= AccessRights.AR_SCOPE_COLLECTIONS_ReadUserAny
            #if at least one write perrmission is set
            if token_scope & AccessRights.AR_SCOPE_COLLECTIONS_WriteUserAny:
                token_scope |= AccessRights.AR_SCOPE_COLLECTIONS_WriteUserAny
        return needed_scope & token_scope != 0
    """
    Generates random token for user
    """
    @classmethod
    def MakeToken(cls, user_obj, scope):
        assert isinstance(user_obj, User)
        if(user_obj is not None):
            a = AccessToken(access_scope = user_obj.access_scope & scope, access_key = penguin.utils.randstr(64), link_user = user_obj)
            a.save()
            return a
        else:
            return None

    @classmethod
    def GetHashFromPath(cls, path):
        #find "hash=" str and remove all chars after it until & char or end
        pos = path.rfind("hash=") 
        if pos != -1:
            end_pos = path.find("&", pos)
            to_hash = hash[:pos]+hash[end_pos+1:]+access_key
            asktechnopark.utils.security.get_hash(to_hash)
        return ""



##############          TAG         ##########

class Tag(models.Model):

    primary_name = models.CharField(max_length = 50)
    
    calc_total_posts    = models.PositiveIntegerField(blank = True, default = 0)
    calc_total_rating   = models.PositiveIntegerField(blank = True, default = 0, db_index = True)



##############          POST        ##########


class PostType(enum.IntEnum):
    PT_MIN      =   0

    PT_QUESTION =   0
    PT_ANSWER   =   1

    PT_MAX      =   1

class Post(models.Model):

    url                 =   models.CharField(max_length = 256)

    link_tags           =   models.ManyToManyField(Tag)
    link_parent_post    =   models.ForeignKey('self')
    link_user           =   models.ForeignKey(User,models.SET_NULL, null = True)
    
    text                =   models.TextField()
    title               =   models.CharField(max_length = 256)
    type                =   IntegerRangeField(max_value = PostType.PT_MAX, min_value = PostType.PT_MAX)
    date                =   models.DateTimeField()

    pic                 =   models.ImageField(upload_to="/uploads/")



    calc_rating         =   models.PositiveIntegerField(null = True, blank = True)
    calc_comments       =   models.PositiveIntegerField(null = True, blank = True)
    calc_linked_posts   =   models.PositiveIntegerField(null = True, blank = True)


    @staticmethod
    def UrlFromHeader(header:str, id:int):
        import re, string; 
        import unidecode
        url = ""
        hd = header.strip()
        hd = hd[:min(245,len(hd))].replace(' ','_')
        pattern = re.compile('[\W]+')
        
        hd = unidecode.unidecode(hd).lower()
        hd = pattern.sub('', hd)
        url = hd+'_'+id.__str__()
        return url

    @classmethod
    def CreatePost(type, author,  title, text, pic = None, date = None):
        pass



##############          COMMENT        ##########
class Comment(models.Model):

    link_parent_post    =   models.ForeignKey(Post)
    link_user           =   models.ForeignKey(User)

    text                =   models.TextField()

