

#templating
import jinja2

import os
import re

#Google app engine imports
import webapp2

#TODO take out once refactoring is done
import main

import models

import functions



def routes():
    """
    function to organize all of the routes
    """
    app = webapp2.WSGIApplication([('/', Main),
                               ('/posts', Posts),
                               ('/create', CreatePost),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/posts/([0-9]+)', Posts),
                               ('/register', Register),
                               ('/comment', Comment)],
                              debug=True)
    return app

class MainHandler(webapp2.RequestHandler):
    """
    The MainHandler class is the parent class used for all routes
    **params - all extra parameters
    """


    def render(self, template, **kw):
        """
        function to simply render the text using the views folder by default
        """
        self.response.out.write(main.render_str(template, **kw))

    def write(self, *a, **kw):
        """
        function to simply render the text using the views folder by default
        """
        self.response.out.write(*a, **kw)


    #TODO create expire time
    def set_secure_cookie(self, name, user_id):
        """
        function to create cookie based on user id
        """
        #TODO take out main.
        cookie_val = functions.make_secure_val(user_id)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """
        function to read cookie of user
        """
        cookie_val = self.request.cookies.get(name)
        #both of the following need to be true
        #TODO take out main.
        return cookie_val and functions.check_secure_val(cookie_val)

    #login and set a secure cookie based on the user's id
    def login(self, user):
        """
        function to login user and set session cookie
        """
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
class Posts(MainHandler):
    def get(self, post_id):
        key = models.db.Key.from_path('Post', int(post_id), parent=models.blog_key())
        post = models.db.get(key)
        posts = greetings = models.Post.all().order('-created')
        if self.request.get("action"):
            if self.request.get("action") == "delete":
                #delete post
                post.delete()
                self.render("main.html", posts = posts, user = self.user)
            elif self.request.get("action") == "edit":
                self.render("edit.html", post = post)
            elif self.request.get("action") == "like":
                post.likes = post.likes + 1
                post.put()
                like = models.Likes(parent = models.likes_key(), post_id=post.key().id(), author = self.user.name)
                like.put()
                self.render("main.html", posts = posts, user = self.user)
        else:
            #get all comments with the post id
            comments = greetings = models.Comments.all()
            if not post:
                self.error(404)
                return
            #rener the posts page with the comments template
            self.render("posts.html", post = post, user = self.user, comments = comments)
    def post(self, post_id):
        #postdate for editting post
        subject = self.request.get("subject")
        content = self.request.get("content")
        key = models.db.Key.from_path('Post', int(post_id), parent=models.blog_key())
        post = models.db.get(key)
        post.subject = subject
        post.content = content
        post.put()
        self.redirect('/posts/' + post_id)

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

class Comment(MainHandler):
    def get(self):
        post_id = self.request.get("post")
        key = models.db.Key.from_path('Post', int(post_id), parent=models.blog_key())
        post = models.db.get(key)
        self.render("comment.html", post = post)

    def post(self):
        comment = self.request.get('comment')
        post_id = int(self.request.get('post_id'))

        if comment:
            c = models.Comments(parent = models.comments_key(), author = self.user.name, comment = comment, post_id = post_id)
            c.put()
            key = models.db.Key.from_path('Post', int(post_id), parent=models.blog_key())
            post = models.db.get(key)
            comments = greetings = models.Comments.all().filter('post_id =', post_id)
            post.comments = post.comments + 1
            post.put()
            self.render("posts.html", post = post, user = self.user, comments = comments)
        else:
            error = "comment, please!"
            self.render("create.html", comment=comment, error=error)


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
