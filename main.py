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

from google.appengine.ext import ndb

import jinja2
import webapp2


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



#
# Data model
#
class User(ndb.Model):

    name = ndb.StringProperty(required=True)
    hashed_password = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def get_user_by_name(cls, name):
        return cls.query(User.name == name).get()


class Article(ndb.Model):
    """Article model, represents a blog post."""

    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    author = ndb.StructuredProperty(User)



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
        self.render("create_post.html", post=None)

    @login_required
    def post(self):

        # get the subject and content from the posted form
        post = Article(
            subject=self.request.get('subject'),
            content=self.request.get('content'),
            author=self.user)

        if post.subject and post.content:

            # save the new post in the datastore and return a key
            post_key = post.put()

            post_key = post_key.urlsafe()
            # redirect to the post page
            self.redirect('/blog/post/%s' % post_key)

        else:
            # reload the page, keeping existing input, add an error message
            error = "we need both a subject and some content"
            self.render('create_post.html', post=post, error=error)


class UpdatePost(BaseHandler):
    """Handle update post requests."""

    @login_required
    def get(self, post_key):

        # retrieve the key from the url string
        post_key = ndb.Key(urlsafe=post_key)

        # retrieve the post from the key
        post = post_key.get()

        self.author_required(post)

        # render the page with the post
        self.render("create_post.html", post=post)

    @login_required
    def post(self, post_key):

        # retrieve the key from the url string
        post_key = ndb.Key(urlsafe=post_key)

        # retrieve the post from the key
        post = post_key.get()

        self.author_required(post)

        # retrieve the posted subject and content
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user

        post.subject = subject
        post.content = content
        post.author = author

        if subject and content:

            # update the post
            post.put()
            self.render("detail_post.html", post=post)

        else:
            # reload the page, keeping existing input
            # and adding an error message
            error = "we need both a subject and some content"
            self.render('create_post.html', error=error, post=post)


class DetailPost(BaseHandler):
    """Display the details of a post."""

    def get(self, post_key):

        # retrieve the key from the url string
        post_key = ndb.Key(urlsafe=post_key)

        # retrieve the post from the key
        post = post_key.get()

        self.render("detail_post.html", post=post)


class DeletePost(BaseHandler):
    """Handle delete post requests."""

    @login_required
    def get(self, post_key):

        # retrieve the key from th url string
        post_key = ndb.Key(urlsafe=post_key)
        post = post_key.get()

        self.author_required(post)

        # delete the key (and the post associated with it)
        post_key.delete()

        # go to confirmation page (add a small delay of 0.5 seconds 
        # before redirecting so datastore has time to update
        time.sleep(0.5)
        self.redirect('/blog/')


class Register(BaseHandler):

    def get(self):
        self.render("register.html", user=None)

    def post(self):
        
        name = self.request.get('name')
        password = self.request.get('password')
        email = self.request.get('email')

        user = User.get_user_by_name(name)
        logging.info(user)

        if user:
            
            error = "Name already used"
            self.render('register.html', user=None, error=error)
            return

        hashed_password = make_pw_hash(name, password)

        user = User(
            name=name,
            hashed_password=hashed_password,
            email=email)

        if (user.name and user.hashed_password):

            user.put()
            self.set_secure_cookie("user_name", str(user.name))
            time.sleep(0.5)
            self.redirect('/blog/')

        else:
            error = "You need to fill out your name and password"
            self.render('register.html', user=user, error=error)


class Login(BaseHandler):

    def get(self):
        self.render("login.html", user=None)

    def post(self):
        
        name = self.request.get('name')
        password = self.request.get('password')

        if name and password:

            user = User.get_user_by_name(name)
            logging.info(user)

            if user and check_pw_hash(name, password, user.hashed_password):
                self.set_secure_cookie("user_name", str(user.name))
                self.redirect('/blog/')

            else:
                error = "Invalid login"
                self.render('login.html', name=name, error=error) 

        else:
            error = "You need to fill out your name and password"
            self.render('login.html', name=name, error=error)


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
