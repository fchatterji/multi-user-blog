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
import time
import hmac
import string
import hashlib
import random
import re

from google.appengine.ext import ndb

import jinja2
import webapp2

from models import User, Article, Comment, Like

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(
        os.path.join(os.path.dirname(__file__), 'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)




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
    salt = h.split(',', 1)[1]

    if h == make_pw_hash(name, pw, salt=salt):
        return True
    else:
        return False



def login_required(handler_method):
    """..."""
    def check_login(self, *args):
        if not self.user:
            self.redirect("/blog/login")
            return
        else:
            handler_method(self, *args)
    return check_login


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,50}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,50}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

SUBJECT_RE = re.compile(r"^.{3,200}$")
def valid_subject(subject):
    return subject 

CONTENT_RE = re.compile(r"^.{3,}$")
def valid_content(content):
    return content


def validate_signup_form(username, password, verify, email):
    have_error = False
    errors = {}

    user = User.get_user_by_name(username)

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


def validate_update_post_form(subject, content, original_author, user):
    have_error = False
    errors = {}

    if not valid_subject(subject):
        errors['error_subject'] = "The subject must be between 3 and 200 characters long."
        have_error = True

    if not valid_content(content):
        errors['error_content'] = "The content must be at least 3 characters long."
        have_error = True

    if user is not original_author:
        errors["error_author"] = "You must be the original author of a post to edit it."

    if have_error:
        return (False, errors)
    else:
        return (True, None)



def validate_login_form(username, password):
    have_error = False
    errors = {}

    user = User.get_user_by_name(username)

    if not valid_username(username):
        errors['error_username'] = "That's not a valid username."
        have_error = True

    elif not user:
        errors['error_username'] = "This username doesn't exist."
        have_error = True

    if not valid_password(password):
        errors['error_password'] = "That wasn't a valid password."
        have_error = True

    elif user and check_pw_hash(username, password, user.hashed_password):
        errors['error_password'] = "The password is incorrect."
        have_error = True

    if have_error:
        return (False, errors)
    else:
        return (True, None)


def validate_delete(original_author, user):
    have_error = False
    errors = {}

    if user is not original_author:
        errors["error_author"] = "You must be the original author of a post to delete it."

    if have_error:
        return (False, errors)
    else:
        return (True, None)


#
# Handlers
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

        self.user = user_name and User.get_user_by_name(user_name)

    def check_author(self, post):
        return self.user == post.author



class Home(BaseHandler):
    """Handle home page requests."""

    def get(self):
        q = Article.gql("ORDER BY created DESC")
        posts = q.fetch()

        self.render('index.html', posts=posts, user=self.user)


class CreatePost(BaseHandler):
    """Handle new post requests."""

    @login_required
    def get(self):
        self.render("create_post.html", errors=None)

    @login_required
    def post(self):

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user

        is_valid, errors = validate_create_post_form(subject, content)

        if is_valid:

            post = Article(subject=subject, content=content, author=author)
            # save the new post in the datastore and return a key
            post_key = post.put()

            # redirect to the post page
            post_key = post_key.urlsafe()
            self.redirect('/blog/post/%s' % post_key)

        else:
            self.render('create_post.html', subject=subject, content=content, errors=errors)


class UpdatePost(BaseHandler):
    """Handle update post requests."""

    @login_required
    def get(self, post_key):

        # retrieve the post from the key
        post_key = ndb.Key(urlsafe=post_key)
        post = post_key.get()

        subject = post.subject
        content = post.content
        author = post.author.name

        self.render("update_post.html", subject=subject, content=content, author=author, errors=None)


    @login_required
    def post(self, post_key_url):

        # retrieve the post from the key
        post_key = ndb.Key(urlsafe=post_key_url)
        post = post_key.get()

        subject = self.request.get('subject')
        content = self.request.get('content')

        author = post.author.name
        user = self.user

        is_valid, errors = validate_update_post_form(subject, content, author, user)

        if is_valid:

            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/post/%s' % post_key_url)

        else:
            self.render('update_post.html', subject=subject, content=content, author=author, errors=errors)


class DetailPost(BaseHandler):
    """Display the details of a post."""

    def get(self, post_key):

        # retrieve the post from the key
        post_key = ndb.Key(urlsafe=post_key)
        post = post_key.get()

        subject = post.subject
        content = post.content
        author = post.author.name

        self.render("detail_post.html", subject=subject, content=content, post=post, author=author, errors=None)


class DeletePost(BaseHandler):
    """Handle delete post requests."""

    @login_required
    def get(self, post_key):

        # retrieve the key from th url string
        post_key = ndb.Key(urlsafe=post_key)
        post = post_key.get()

        subject = post.subject
        content = post.content
        author = post.author.name
        user = self.user

        is_valid, errors = validate_delete(author, user)

        if is_valid:
            post_key.delete()
            time.sleep(0.5)
            self.redirect('/blog/')

        else:
            self.render("detail_post.html", subject=subject, content=content, errors=errors)


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
                email=email)

            user.put()
            self.set_secure_cookie("user_name", str(user.name))
            time.sleep(0.5)
            self.redirect('/blog/')

        else:
            self.render('register.html', name=username, email=email, errors=errors)


class Login(BaseHandler):

    def get(self):
        self.render("login.html", errors=None)

    def post(self):
        
        username = self.request.get('name')
        password = self.request.get('password')

        is_valid, errors = validate_login_form(username, password)

        if is_valid:
            user = User.get_user_by_name(username)
            self.set_secure_cookie("user_name", str(user.name))
            time.sleep(0.5)
            self.redirect('/blog/')

        else:
            self.render('login.html', name=username, errors=errors)


class Logout(BaseHandler):

    def get(self):
        self.clear_cookie()
        self.redirect('/blog/')


#
# url scheme
#
app = webapp2.WSGIApplication([
    ('/blog/?', Home),
    ('/blog/register', Register),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/create', CreatePost),
    ('/blog/post/(\S+)', DetailPost),
    ('/blog/update/(\S+)', UpdatePost),
    ('/blog/delete/(\S+)', DeletePost)],
    debug=True)
