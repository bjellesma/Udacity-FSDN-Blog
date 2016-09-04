"""
File: models.py
Author: William Jellesma

This file houses all of the database schema and functions related to the db
"""

#database modules
from google.appengine.ext import db

#app modules
import main
import functions

"""
Class: Post
Inherits: db.Model class

The database schema and class functions for the Post table is contained here
"""
class Post(db.Model):
    subject = db.StringProperty(required = True)
    author = db.StringProperty()
    likes = db.IntegerProperty()
    comments = db.IntegerProperty()
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    """
    Args: self (class reference), user (GQL value), likes (GQL value, default = '')

    Returns:
    renders the posts with all of the relavent data
    """
    def render(self, user, likes = ''):
        self._render_text = self.content.replace('\n', '<br>')
        return main.render_str("post.html", p = self, user = user, likes = likes)

"""
Class: Comments
Inherits: db.Model class

The database schema and class functions for the Comments table is contained here
"""
class Comments(db.Model):
    post_id = db.IntegerProperty()
    author = author = db.StringProperty()
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    """
    Args: self (class reference)

    Returns:
    renders the comment for the post
    """
    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')
        return main.render_str("comment_view.html", c = self)

"""
Class: Likes
Inherits: db.Model class

The database schema and class functions for the Likes table is contained here
"""
class Likes(db.Model):
    post_id = db.IntegerProperty()
    author = author = db.StringProperty()

"""
Class: User
Inherits: db.Model class

The database schema and class functions for the User table is contained here
"""
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    #the @ symbol makes this a decorator so it is annotated
    #cls is another way to use self
    #cls should technically be used for class methods
    """
    Args: cls (class reference), uid (integer)

    Returns:
    User object by id
    """
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    """
    Args: cls (class reference), name (string)

    Returns:
    User object by name
    """
    @classmethod
    def by_name(cls, name):
        user = User.all().filter('name =', name).get()
        return user

    """
    Args: cls (class reference), name (string), pw (string), email (string, default = None)

    Returns:
    User object to be put into database
    """
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = functions.make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    """
    Args: cls (class reference), name (string), pw (string)

    Returns:
    user object
    """
    @classmethod
    #called cls.by_name instead of User.by_name() so that we can override the function
    #TODO change other use references
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user and functions.valid_pw(name, pw, user.pw_hash):
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
