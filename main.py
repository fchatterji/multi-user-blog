#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2016 Google Inc.
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
# IMPORTS
#
import os
import logging
import hmac
import string
import hashlib
import random
import re
import json

from google.appengine.ext import ndb

import jinja2
import webapp2

from models import User, Article, Comment, Blog

#
# Constants
#
JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(
        os.path.join(os.path.dirname(__file__), 'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

def blog_key():
    blog_key = Blog.query(Blog.name == "myblog").get().key
    return blog_key

blog_key = blog_key()
#
# Security functions
#
def hash_str(s):
    return hmac.new("secret", s).hexdigest()


def make_secure_val(s):
    return "%s,%s" % (s, hash_str(s))


def check_secure_val(h):
    h = h.split(',', 1)
    if hash_str(h[0]) == h[1]:
        return h[0]
    else:
        return None


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=make_salt()):
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def check_pw_hash(name, pw, h):
    logging.info(name)
    logging.info(pw)
    logging.info(h)

    salt = h.split(',', 1)[1]

    if h == make_pw_hash(name, pw, salt=salt):
        logging.info(make_pw_hash(name, pw, salt=salt))
        return True
    else:
        return False


#
# Login
#
def login_required(handler_method):

    def check_login(self, *args, **kwargs):
        if not self.user:
            self.redirect_to("login")
            return
        else:
            return handler_method(self, *args, **kwargs)
    return check_login

def article_author_required(handler_method):

    def wrapper(self, *args, **kwargs):
        post_key_url = kwargs['post_key_url']
        post_key = ndb.Key(urlsafe=post_key_url)
        post = post_key.get()

        if self.user.name != post.author.name:
            self.redirect_to('home')
            return

        else:
            return handler_method(self, *args, **kwargs)

    return wrapper

def comment_author_required(handler_method):

    def wrapper(self, *args, **kwargs):
        comment_key_url = kwargs['comment_key_url']
        comment_key = ndb.Key(urlsafe=comment_key_url)
        comment = comment_key.get()

        if self.user.name != comment.author.name:
            self.redirect_to('home')
            return

        else:
            return handler_method(self, *args, **kwargs)

    return wrapper



#
# Form validation
#
def valid_username(username):
    user_re = re.compile(r"^[a-zA-Z0-9_-]{3,50}$")
    return username and user_re.match(username)


def valid_password(password):
    password_re = re.compile(r"^.{3,50}$")
    return password and password_re.match(password)


def valid_email(email):
    email_re = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or email_re.match(email)


def valid_subject(subject):
    subject_re = re.compile(r"^.{3,200}$")
    return subject and subject_re.match(subject)


def valid_content(content):
    content_re = re.compile(r"^.{3,}$")
    return content and content_re.match(content)


def validate_signup_form(username, password, verify, email):
    have_error = False
    errors = {}

    user = User.query(User.name == username, ancestor=blog_key).get()

    if not valid_username(username):
        errors['error_username'] = "That's not a valid username."
        have_error = True

    elif user:
        errors['error_username'] = "This username is already taken."
        have_error = True

    if not valid_password(password):
        errors['error_password'] = "That wasn't a valid password."
        have_error = True

    elif password != verify:
        errors['error_verify'] = "Your passwords didn't match."
        have_error = True

    if not valid_email(email):
        errors['error_email'] = "That's not a valid email."
        have_error = True

    if have_error:
        return (False, errors)
    else:
        return (True, None)


def validate_create_post_form(subject, content):
    have_error = False
    errors = {}

    if not valid_subject(subject):
        errors['error_subject'] = "The subject must be between 3 and 200 characters long."
        have_error = True

    if not valid_content(content):
        errors['error_content'] = "The content must be at least 3 characters long."
        have_error = True

    if have_error:
        return (False, errors)
    else:
        return (True, None)


def validate_update_post_form(subject, content):
    have_error = False
    errors = {}

    if not valid_subject(subject):
        errors['error_subject'] = "The subject must be between 3 and 200 characters long."
        have_error = True

    if not valid_content(content):
        errors['error_content'] = "The content must be at least 3 characters long."
        have_error = True

    if have_error:
        return (False, errors)
    else:
        return (True, None)


def validate_login_form(username, password):
    have_error = False
    errors = {}

    user = User.query(User.name == username, ancestor=blog_key).get()
    logging.info(user)
    logging.info(check_pw_hash(username, password, user.hashed_password))

    if not valid_username(username):
        errors['error_username'] = "That's not a valid username."
        have_error = True

    elif not user:
        errors['error_username'] = "This username doesn't exist."
        have_error = True

    if not valid_password(password):
        errors['error_password'] = "That wasn't a valid password."
        have_error = True

    elif not(user and check_pw_hash(username, password, user.hashed_password)):
        errors['error_password'] = "The password is incorrect."
        have_error = True

    if have_error:
        return (False, errors)
    else:
        return (True, None)



#
# Base handler
#
class BaseHandler(webapp2.RequestHandler):
    """Base request handler class with helper functions."""

    def render(self, template, **kw):
        """Render a template, given the template and a context."""
        template = JINJA_ENVIRONMENT.get_template(template)
        self.response.write(template.render(**kw))

    def set_secure_cookie(self, cookie_name, cookie_value):
        cookie_value = make_secure_val(cookie_value)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (cookie_name, cookie_value))

    def read_secure_cookie(self, name):
        cookie_value = self.request.cookies.get(name)
        return cookie_value

    def clear_cookie(self):
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % ("user_name", ""))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_name = self.read_secure_cookie('user_name')
        user = User.query(User.name == user_name, ancestor=blog_key).get()

        self.user = user
#
# Handlers
#
class Home(BaseHandler):
    """Handle home page requests."""

    def get(self):
        posts = Article.query(ancestor=blog_key).fetch()

        logging.info(posts)

        self.render('index.html', posts=posts, user=self.user, errors=None)



class CreatePost(BaseHandler):
    """Handle new post requests."""

    @login_required
    def get(self):
        self.render("create_post.html", errors=None, user=self.user)

    @login_required
    def post(self):

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user

        is_valid, errors = validate_create_post_form(subject, content)

        if is_valid:

            post = Article(subject=subject, content=content, author=author, parent=blog_key, comments=[])
            post.put()

            # redirect to the post page
            self.redirect_to('home')

        else:
            self.render(
                'create_post.html',
                subject=subject,
                content=content,
                errors=errors,
                user=self.user
            )


class DetailPost(BaseHandler):
    """Display the details of a post."""

    @login_required
    def get(self, post_key_url):

        """
        # retrieve the post from the key
        post_key = ndb.Key(urlsafe=post_key_url)
        post = post_key.get()

        comments = Comment.query(Comment.article == post_key, ancestor=blog_key).fetch()

        self.render(
            "detail_post.html",
            post=post,
            comments=comments,
            errors=None,
            user=self.user
        )"""


class UpdatePost(BaseHandler):
    """Handle update post requests."""


    @login_required
    @article_author_required
    def get(self, post_key_url):

        post_key = ndb.Key(urlsafe=post_key_url)
        post = post_key.get()

        self.render(
            "update_post.html",
            post=post,
            errors=None,
            user=self.user
        )

    @login_required
    @article_author_required
    def post(self, post_key_url):

        subject = self.request.get('subject')
        content = self.request.get('content')

        is_valid, errors = validate_update_post_form(subject, content)

        # retrieve the post from the key
        post_key = ndb.Key(urlsafe=post_key_url)
        post = post_key.get()

        if is_valid:

            post.subject = subject
            post.content = content
            post.put()
            self.redirect_to('home')

        else:
            self.render(
                'update_post.html',
                post=post,
                errors=errors,
                user=self.user
            )






class DeletePost(BaseHandler):
    """Handle delete post requests."""

    @login_required
    @article_author_required
    def get(self, post_key_url):

        # retrieve the key from the url string
        post_key = ndb.Key(urlsafe=post_key_url)

        post_key.delete()
        self.redirect_to('home')



class CreateComment(BaseHandler):

    @login_required
    def post(self, post_key_url):

        author = self.user
        content = self.request.get("content")
        post_key = ndb.Key(urlsafe=post_key_url)
        post = post_key.get()
        logging.info(post)
        logging.info(post.content)
        logging.info(post.comments)

        comment = Comment(content=content, author=author, parent=blog_key)
        comment.put()

        post.comments.append(comment)
        logging.info(post)
        post.put()


        self.redirect_to("home")


class UpdateComment(BaseHandler):

    @login_required
    @comment_author_required
    def get(self, comment_key_url):

        # retrieve the post from the key
        comment_key = ndb.Key(urlsafe=comment_key_url)
        comment = comment_key.get()

        self.render(
            "update_comment.html",
            comment=comment,
            user=self.user
        )

    @login_required
    @comment_author_required
    def post(self, comment_key_url):

        comment_key = ndb.Key(urlsafe=comment_key_url)
        comment = comment_key.get()

        comment.content = self.request.get('content')
        comment.put()
        self.redirect_to('home')



class DeleteComment(BaseHandler):

    @login_required
    @comment_author_required
    def get(self, comment_key_url):
        comment_key = ndb.Key(urlsafe=comment_key_url)

        comment_key.delete()
        self.redirect_to('home')



class Register(BaseHandler):

    def get(self):
        self.render("register.html", errors=None)


    def post(self):
        
        username = self.request.get('name')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        is_valid, errors = validate_signup_form(username, password, verify, email)

        if is_valid:
            hashed_password = make_pw_hash(username, password)

            user = User(
                name=username,
                hashed_password=hashed_password,
                email=email,
                parent=blog_key
            )
            logging.info(user)
            user.put()
            self.set_secure_cookie("user_name", str(user.name))
            self.redirect_to('home')

        else:
            self.render(
                'register.html',
                name=username,
                email=email,
                errors=errors,
                user=self.user
            )


class Login(BaseHandler):

    def get(self):
        self.render("login.html", errors=None)

    def post(self):
        
        username = self.request.get('name')
        password = self.request.get('password')

        is_valid, errors = validate_login_form(username, password)

        if is_valid:
            user = User.query(User.name == username, ancestor=blog_key).get()
            self.set_secure_cookie("user_name", str(user.name))

            self.redirect_to('home')

        else:
            self.render('login.html', name=username, errors=errors, user=self.user)


class Logout(BaseHandler):

    def get(self):
        self.clear_cookie()
        self.redirect_to('home')





class Like(BaseHandler):

    @login_required
    def post(self):
        post_key_url = self.request.get('post_key_url')
        post_key = ndb.Key(urlsafe=post_key_url)
        post = post_key.get()

        logging.info(self.user.key)
        logging.info(post.liked_by)

        if self.user.key in post.liked_by:
            post.likes -= 1
            post.liked_by = [user_key for user_key in post.liked_by if user_key != self.user.key]
            post.put()
            is_liked = False
            self.response.write(json.dumps({'likes': post.likes, 'is_liked': is_liked}))

        else:
            post.likes += 1
            post.liked_by.append(self.user.key)
            post.put()
            is_liked = True
            self.response.write(json.dumps({'likes': post.likes, 'is_liked': is_liked}))




class Unlike(BaseHandler):

    @login_required
    def post(self):
        post_key_url = self.request.get('post_key_url')
        post_key = ndb.Key(urlsafe=post_key_url)
        post = post_key.get()



        self.response.write(post.likes)




app = webapp2.WSGIApplication([

    webapp2.Route(r'/blog/', handler=Home, name='home'),

    webapp2.Route(r'/blog/register', handler=Register, name='register'),
    webapp2.Route(r'/blog/login', handler=Login, name='login'),
    webapp2.Route(r'/blog/logout', handler=Logout, name='logout'),

    webapp2.Route(r'/blog/create', handler=CreatePost, name='create_post'),
    webapp2.Route(r'/blog/update/<post_key_url:\S+>', handler=UpdatePost, name='update_post'),
    webapp2.Route(r'/blog/delete/<post_key_url:\S+>', handler=DeletePost, name='delete_post'),

    webapp2.Route(r'/blog/comment/create/<post_key_url:\S+>', handler=CreateComment, name='create_comment'),
    webapp2.Route(r'/blog/comment/update/<comment_key_url:\S+>', handler=UpdateComment, name='update_comment'),
    webapp2.Route(r'/blog/comment/delete/<comment_key_url:\S+>', handler=DeleteComment, name='delete_comment'),

    webapp2.Route(r'/blog/like', handler=Like, name='like'),
    webapp2.Route(r'/blog/unlike', handler=Unlike, name='unlike')
],

    debug=True
)
