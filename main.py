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

#TODO take out once refactoring is done
#Google app engine imports
import webapp2



#modules for securing information
import jinja2



#database, views, routes
import models

import routes

import webapp2

import os
template_dir = os.path.join(os.path.dirname(__file__), 'views')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#use /templates as the default dir for jina templates
def render_str(template, **params):
    """
    function to render the template and any extra parameters
    used in MainHandler.render
    """
    t = jinja_env.get_template(template)
    return t.render(params)











#renders the post with all of the necessary content
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)




class Posts(routes.MainHandler):
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

class CreatePost(routes.MainHandler):
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

class Comment(routes.MainHandler):
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


class Login(routes.MainHandler):

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

class Logout(routes.MainHandler):
    #logs out user and redirects them to the main page
    def get(self):
        self.logout()
        self.redirect('/')

class Register(routes.MainHandler):

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


#routes
app = routes.routes()
