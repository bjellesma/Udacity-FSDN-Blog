from google.appengine.ext import db
import main
#this is the class to hold the Post table
class Post(db.Model):
    subject = db.StringProperty(required = True)
    author = db.StringProperty()
    likes = db.IntegerProperty()
    comments = db.IntegerProperty()
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)


    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        return main.render_str("post.html", p = self, user = user)

class Comments(db.Model):
    subject = db.StringProperty(required = True)
    author = db.StringProperty()
    likes = db.IntegerProperty()
    comments = db.IntegerProperty()
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)


class Likes(db.Model):
    post_id = db.IntegerProperty()
    author = author = db.StringProperty()

#class for the user database
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    #the @ symbol makes this a decorator so it is annotated
    #cls is another way to use self
    #cls should technically be used for class methods
    #looks up user by ID... Very Useful
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    #looks up full user object by name
    @classmethod
    def by_name(cls, name):
        user = User.all().filter('name =', name).get()
        return user

    #function to simply create User object that we can later store in the database
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    #called cls.by_name instead of User.by_name() so that we can override the function
    #TODO change other use references
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user and main.valid_pw(name, pw, user.pw_hash):
            return user

#simple functions to get database keys
#These functions are not required but they are good practice
def blog_key():
    return db.Key.from_path('blogs', 'Post')

def users_key(group = 'default'):
    return db.Key.from_path('users', 'User')
def comments_key():
    return db.Key.from_path('comments', 'Comments')

def likes_key(group = 'default'):
    return db.Key.from_path('likes', 'likes')
