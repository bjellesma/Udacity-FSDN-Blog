#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import webapp2
import jinja2
import random
import hashlib
import hmac
from string import letters
from google.appengine.ext import db
#use /templates as the default dir for jina templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#normally this secret is kept in a seperate module
secret = 'doctorWho'

#takes in a template and any extra params and renders the template
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

#makes a secure val based on the user's id
def make_secure_val(user_id):
    return '%s|%s' % (user_id, hmac.new(secret, user_id).hexdigest())

#function to test if value is the same secure value made by make_secure_val()
#again, based on the user id
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class MainHandler(webapp2.RequestHandler):
#the following functions are handler functions

    #basically uses self.write in a shorter form
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    #creates cookie based on id
    #TODO create expire time
    def set_secure_cookie(self, name, user_id):
        cookie_val = make_secure_val(user_id)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    #reads the cookie based on the name we've called the cookie
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        #both of the following need to be true
        return cookie_val and check_secure_val(cookie_val)

    #login and set a secure cookie based on the user's id
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    #logout the user by blanking out their cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
    #checks if user is logged in
    #reads a cookie
    #TODO use on main.html
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


#renders the post with all of the necessary content
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class Main(MainHandler):
    #Here we are taking the 10 most recent posts and passing them to main.html so that we can use them
    def get(self):
        if self.user:
            username = self.user.name
        else:
            username = ''
        posts = greetings = Post.all().order('-created')
        self.render("main.html", posts = posts, username = username)

#makes a random string of 5 letters for use in salting passwords
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

##makes a password using sha256
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    #returns salt used as well as the hash
    return '%s,%s' % (salt, h)

#function to check your entered password against the password in the db
def valid_pw(name, password, h):
    #the salt is the first comma seperated parameter stored
    salt = h.split(',')[0]
    #only returns h if it is equal to the hashed password in the database
    return h == make_pw_hash(name, password, salt)

class Posts(MainHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("posts.html", post = post)

#this is the class to hold the Post table
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

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
        if user and valid_pw(name, pw, user.pw_hash):
            return user

class CreatePost(MainHandler):
    def get(self):
        self.render("create.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/posts/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("create.html", subject=subject, content=content, error=error)

class Login(MainHandler):

    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        successful_login = User.login(username, password)
        #if we were able to validate the user
        #login the user and direct them to the main page
        if successful_login:
            #refers to the login handler function
            #you can also tell by the parameters
            self.login(successful_login)
            #TODO change to render the welcome screen
            self.redirect('/')
        #else, spit out the errors
        else:
            error = 'That username and/or password is invalid'
            self.render('login.html', error = error)

class Logout(MainHandler):
    #logs out user and redirects them to the main page
    def get(self):
        self.logout()
        self.redirect('/')

class Register(MainHandler):

    def get(self):
        self.render("register.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        #the following variable will return a username if there is a name conflict
        notUniqueUser = User.by_name(username)

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if notUniqueUser:
            params['user_conflict'] = "That user already exists. Please pick another username"
            have_error = True

        #render the login form with any errors if present
        if have_error:
            self.render('register.html', **params)
        else:
            user = User.register(username, password, email)
            #put() will actually commit the user to the database
            user.put()
            self.login(user)
            self.redirect('/')

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


#simple functions to get database keys
#These functions are not required but they are good practice
def blog_key():
    return db.Key.from_path('blogs', 'Post')

def users_key(group = 'default'):
    return db.Key.from_path('users', 'User')

#routes
app = webapp2.WSGIApplication([('/', Main),
                               ('/posts', Posts),
                               ('/create', CreatePost),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/posts/([0-9]+)', Posts),
                               ('/register', Register)],
                              debug=True)
