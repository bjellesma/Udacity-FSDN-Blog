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
import models
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
        self.user = uid and models.User.by_id(int(uid))


#renders the post with all of the necessary content
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class Main(MainHandler):
    #Here we are taking the 10 most recent posts and passing them to main.html so that we can use them
    def get(self):
        #set the user if they are logged in
        #else set them to an empty string
        if self.user:
            user = self.user
        else:
            user = ''
        posts = greetings = models.Post.all().order('-created')
        self.render("main.html", posts = posts, user = user)

    def post(self):
        post_id = int(self.request.get('post_id'))
        author = self.request.get('author')
        #create like
        like = models.Likes(parent = models.likes_key(), post_id=post_id, author = author)
        like.put()

        #also update post
        key = models.db.Key.from_path('Post', int(post_id), parent=models.blog_key())
        post = models.db.get(key)
        post.likes = post.likes + 1
        post.put()
        self.redirect('/')

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
        key = models.db.Key.from_path('Post', int(post_id), parent=models.blog_key())
        post = models.db.get(key)

        if not post:
            self.error(404)
            return

        self.render("posts.html", post = post, user = self.user)


class CreatePost(MainHandler):
    def get(self):
        self.render("create.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name

        if subject and content:
            p = models.Post(parent = models.blog_key(), author = author, subject = subject, content = content, likes =0, comments=0)
            #put() will commit the database transaction
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

        successful_login = models.User.login(username, password)
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
        notUniqueUser = models.User.by_name(username)

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
            user = models.User.register(username, password, email)
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




#routes
app = webapp2.WSGIApplication([('/', Main),
                               ('/posts', Posts),
                               ('/create', CreatePost),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/posts/([0-9]+)', Posts),
                               ('/register', Register)],
                              debug=True)
