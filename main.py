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

from google.appengine.api import users
from google.appengine.ext import ndb

import jinja2
import webapp2


JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(
        os.path.join(os.path.dirname(__file__), 'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)




"""def hash_password(password):
    # Hash a password for the first time, with a randomly-generated salt
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed_password

def check_password(password, hashed_password):
    # Check that a unhashed password matches one that has previously been
    # hashed
    return bcrypt.hashpw(password, hashed_password) == hashed_password
"""




#
# Data model
#
class User(ndb.Model):

    name = ndb.StringProperty(required=True)
    hashed_password = ndb.StringProperty(required=True)
    email = ndb.StringProperty()


class Article(ndb.Model):
    """Article model, represents a blog post."""

    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    user = ndb.StructuredProperty(User)




"""
    def set_secure_cookie(self, cookie_name, cookie_value):
        cookie_value = hash_password(cookie_value)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (cookie_name, cookie_value))


"""

#
# Handlers
#
class BaseHandler(webapp2.RequestHandler):
    """Base request handler class with helper functions."""

    def render(self, template, **kw):
        """Render a template, given the template and a context."""
        template = JINJA_ENVIRONMENT.get_template(template)
        self.response.write(template.render(**kw))

    def read_secure_cookie(self, name):
        cookie_value = self.request.cookies.get(name)
        return cookie_value

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)


class Home(BaseHandler):
    """Handle home page requests."""

    def get(self):
        q = Article.gql("ORDER BY created DESC")
        posts = q.fetch()

        self.render('index.html', posts=posts)


class CreatePost(BaseHandler):
    """Handle new post requests."""

    def get(self):
        self.render("create_post.html", post=None)

    def post(self):
        # get the subject and content from the posted form
        post = Article(
            subject=self.request.get('subject'),
            content=self.request.get('content'))

        if post.subject and post.content:

            # save the new post in the datastore and return a key
            post_key = post.put()

            # redirect to the post page
            self.redirect('/blog/post/%s' % post_key.urlsafe())

        else:
            # reload the page, keeping existing input, add an error message
            error = "we need both a subject and some content"
            self.render('create_post.html', post=post, error=error)


class UpdatePost(BaseHandler):
    """Handle update post requests."""

    def get(self, post_key):

        # retrieve the key from the url string
        post_key = ndb.Key(urlsafe=post_key)

        # retrieve the post from the key
        post = post_key.get()

        # render the page with the post
        self.render("create_post.html", post=post)

    def post(self, post_key):

        # retrieve the key from the url string
        post_key = ndb.Key(urlsafe=post_key)

        # retrieve the post from the key
        post = post_key.get()

        # retrieve the posted subject and content
        subject = self.request.get('subject')
        content = self.request.get('content')

        post.subject = subject
        post.content = content

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

    def get(self, post_key):
        # retrieve the key from th url string
        post_key = ndb.Key(urlsafe=post_key)

        # delete the key (and the post associated with it)
        post_key.delete()

        # go to confirmation page (add a small delay of 0.5 seconds before redirecting
        # so datastore has time to update
        time.sleep(0.5)
        self.redirect('/blog/')


class Register(BaseHandler):

    def get(self):
        self.render("register.html", user=None)

    def post(self):
        user = User(
            name=self.request.get('name'),
            password=self.request.get('password'),
            email=self.request.get('email'))

        if not(user.name and user.password):
            error = "You need to fill out your name and password"
            self.render('register.html', user=user, error=error)

        if (user.name and user.password):

            """user_key = user.put()"""

            # redirect to the post page
            self.redirect('/blog/post/%s' % post_key.urlsafe())

        else:
            # reload the page, keeping existing input, add an error message
            pass


#
# url scheme
#
app = webapp2.WSGIApplication([
    ('/blog/?', Home),
    ('/blog/register', Register),
    ('/blog/create', CreatePost),
    ('/blog/post/(\S+)', DetailPost),
    ('/blog/update/(\S+)', UpdatePost),
    ('/blog/delete/(\S+)', DeletePost)],
    debug=True)
