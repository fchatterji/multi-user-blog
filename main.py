#!/usr/bin/env python
# -*- coding: utf-8 -*-


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
#
# CONSTANTS
#
#
JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(
        os.path.join(os.path.dirname(__file__), 'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)


def blog_key():
    """
    Return the key of the blog.

    This is used to do ancestor queries throughout the application, therefore
    guaranteeing strong consistency. See this article for more detail:
    https://cloud.google.com/datastore/docs/articles/balancing-strong-and-eventual-consistency-with-google-cloud-datastore/
    """
    blog_key = Blog.query(Blog.name == "myblog").get().key
    return blog_key

BLOG_KEY = blog_key()


#
#
# Security functions
#
#
def hash_str(s):
    """Return a hash of a string, with the hmac algorithm."""
    return hmac.new("secret", s).hexdigest()


def make_secure_val(s):
    """Return a string and it's hashed value, separated by a comma."""
    return "%s,%s" % (s, hash_str(s))


def check_secure_val(h):
    """Check if a hash is valid."""
    h = h.split(',', 1)
    if hash_str(h[0]) == h[1]:
        return h[0]
    else:
        return None


def make_salt():
    """Return a password salt of 5 random letters."""
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=make_salt()):
    """Hash a name and password, using the sha256 algorithm."""
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def check_pw_hash(name, pw, h):
    """Check if a password hash is valid."""
    salt = h.split(',', 1)[1]

    if h == make_pw_hash(name, pw, salt=salt):
        return True
    else:
        return False


#
#
# Login
#
#
def login_required_or_redirect(handler_method):
    """
    Check if a user is logged in.

    If not redirect to the home page.
    """
    def check_login(self, *args, **kwargs):
        if not self.user:
            self.redirect_to("login")
            return
        else:
            return handler_method(self, *args, **kwargs)
    return check_login


def article_author_required_or_redirect(handler_method):
    """
    Check if the current user is the author of the current post.

    If not, redirect to the home page.
    """
    def wrapper(self, *args, **kwargs):
        post_key_url = kwargs['post_key_url']
        post = Article.by_key_url(post_key_url)

        if self.user.name != post.author.name:
            self.redirect_to('home')
            return

        else:
            return handler_method(self, *args, **kwargs)

    return wrapper


def comment_author_required_or_redirect(handler_method):
    """
    Check if the current user is the author of the current comment.

    If not, redirect to the home page.
    """
    def wrapper(self, *args, **kwargs):
        comment_key_url = kwargs['comment_key_url']
        comment = Comment.by_key_url(comment_key_url)

        if self.user.name != comment.author.name:
            self.redirect_to('home')
            return

        else:
            return handler_method(self, *args, **kwargs)

    return wrapper


#
#
# Form validation
#
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
    return content


def validate_signup_form(username, password, verify, email):
    """
    Validate the signup form.

    If the form is valid, return a tuple of (True, None).
    If the form is not valid, return a tuple of (False, dictionary of
    error messages).
    """
    have_error = False
    errors = {}

    user = User.query(User.name == username, ancestor=BLOG_KEY).get()

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
    """
    Validate the form to create a post.

    If the form is valid, return a tuple of (True, None).
    If the form is not valid, return a tuple of (False, dictionary of
    error messages).
    """
    have_error = False
    errors = {}

    if not valid_subject(subject):
        errors['error_subject'] = """The subject must be between 3 and 200
        characters long."""
        have_error = True

    if not valid_content(content):
        errors['error_content'] = """Come on, only one character is required,
        you can do this!"""
        have_error = True

    if have_error:
        return (False, errors)
    else:
        return (True, None)


def validate_update_post_form(subject, content):
    """
    Validate the form used to update a post.

    If the form is valid, return a tuple of (True, None).
    If the form is not valid, return a tuple of (False, dictionary of
    error messages).
    """
    have_error = False
    errors = {}

    if not valid_subject(subject):
        errors['error_subject'] = """The subject must be between 3 and 200
        characters long."""
        have_error = True

    if not valid_content(content):
        errors['error_content'] = """Come on, only one character is required,
        you can do this!"""
        have_error = True

    if have_error:
        return (False, errors)
    else:
        return (True, None)


def validate_login_form(username, password):
    """
    Validate the login form.

    If the form is valid, return a tuple of (True, None).
    If the form is not valid, return a tuple of (False, dictionary of
    error messages).
    """
    have_error = False
    errors = {}

    user = User.query(User.name == username, ancestor=BLOG_KEY).get()

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
#
# HANDLERS
#
#
class BaseHandler(webapp2.RequestHandler):
    """Base request handler class with helper functions."""

    def render(self, template, **kw):
        """Render a template, given the template and a context."""
        template = JINJA_ENVIRONMENT.get_template(template)
        self.response.write(template.render(**kw))

    def set_secure_cookie(self, cookie_name, cookie_value):
        """Set a cookie with a name and a hashed value."""
        cookie_value = make_secure_val(cookie_value)

        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (cookie_name, cookie_value))

    def read_secure_cookie(self, name):
        """Given a cookie, return it's unhashed value."""
        cookie_value = self.request.cookies.get(name)
        return cookie_value

    def clear_cookie(self):
        """Delete the existing cookie."""
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % ("user_name", ""))

    def initialize(self, *a, **kw):
        """
        Overload the initialize method of the handlers, adding a user property.

        The user property is read from the cookie.
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_name = self.read_secure_cookie('user_name')
        user = User.query(User.name == user_name, ancestor=BLOG_KEY).get()

        self.user = user


class Home(BaseHandler):
    """Handle home page requests."""

    def get(self):
        """Fetch all posts, render the home page."""
        posts = Article.query(ancestor=BLOG_KEY).order(-Article.last_modified).fetch()

        self.render('index.html', posts=posts, user=self.user, errors=None)


class CreatePost(BaseHandler):
    """Handle new post requests."""

    @login_required_or_redirect
    def get(self):
        """Render the create post form."""
        self.render("create_post.html", user=self.user, errors=None)

    @login_required_or_redirect
    def post(self):
        """Fetch the created post, validate it and redirect to home page."""
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user

        is_valid, errors = validate_create_post_form(subject, content)

        if is_valid:
            # create a new post and save it in the datastore
            post = Article(
                subject=subject,
                content=content,
                author=author,
                parent=BLOG_KEY,
                comments=[]
            )

            post.put()

            # redirect to the post page
            self.redirect_to('home')

        else:
            # render the form again, keeping existing input
            self.render(
                'create_post.html',
                subject=subject,
                content=content,
                errors=errors,
                user=self.user
            )


class UpdatePost(BaseHandler):
    """Handle update post requests."""

    @login_required_or_redirect
    @article_author_required_or_redirect
    def get(self, post_key_url):
        """Fetch a post, render the update post form."""
        post = Article.by_key_url(post_key_url)

        self.render(
            "update_post.html",
            post=post,
            errors=None,
            user=self.user
        )

    @login_required_or_redirect
    @article_author_required_or_redirect
    def post(self, post_key_url):
        """Get updated post content, validate it and redirect to home page."""
        subject = self.request.get('subject')
        content = self.request.get('content')

        is_valid, errors = validate_update_post_form(subject, content)

        post = Article.by_key_url(post_key_url)

        if is_valid:
            # update the post and redirect to home page
            post.subject = subject
            post.content = content
            post.put()
            self.redirect_to('home')

        else:
            # render the form again, keeping existing input
            self.render(
                'update_post.html',
                post=post,
                errors=errors,
                user=self.user
            )


class DeletePost(BaseHandler):
    """Handle delete post requests."""

    @login_required_or_redirect
    @article_author_required_or_redirect
    def get(self, post_key_url):
        """Get the post key and delete it."""
        post_key = ndb.Key(urlsafe=post_key_url)

        post_key.delete()
        self.redirect_to('home')


class CreateComment(BaseHandler):
    """Handle create comment requests."""

    @login_required_or_redirect
    def post(self, post_key_url):
        """Get posted comment data, save it and redirect to home page."""
        author = self.user
        content = self.request.get("content")

        # save the comment
        comment = Comment(content=content, author=author, parent=BLOG_KEY)
        comment_key = comment.put()

        # save a reference to the comment in the post.
        post = Article.by_key_url(post_key_url)
        post.comments.append(comment_key)
        post.put()

        self.redirect_to("home")


class UpdateComment(BaseHandler):
    """Handle update comment requests."""

    @login_required_or_redirect
    @comment_author_required_or_redirect
    def get(self, comment_key_url):
        """Fetch the comment, render the update comment form."""
        comment = Comment.by_key_url(comment_key_url)

        self.render(
            "update_comment.html",
            comment=comment,
            user=self.user
        )

    @login_required_or_redirect
    @comment_author_required_or_redirect
    def post(self, comment_key_url):
        """Get posted comment data, save it and redirect to the home page."""
        comment = Comment.by_key_url(comment_key_url)

        comment.content = self.request.get('content')
        comment.put()

        self.redirect_to('home')


class DeleteComment(BaseHandler):
    """Handle delete comment requests."""

    @login_required_or_redirect
    @comment_author_required_or_redirect
    def get(self, comment_key_url, post_key_url):
        """Delete a comment and redirect to home page."""
        comment_key_to_delete = ndb.Key(urlsafe=comment_key_url)
        comment_key_to_delete.delete()

        # update the reference to the comment in the post
        post = Article.by_key_url(post_key_url)

        post.comments = [
            comment_key for comment_key in post.comments
            if comment_key != comment_key_to_delete
        ]

        post.put()

        # redirect to the home page
        self.redirect_to('home')


class Register(BaseHandler):
    """Handle register requests."""

    def get(self):
        """Render the register form."""
        self.render("register.html", errors=None)

    def post(self):
        """Get and validate data, create user and redirect to home page."""
        username = self.request.get('name')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        is_valid, errors = validate_signup_form(
            username,
            password,
            verify,
            email
        )

        if is_valid:
            # create and save the user
            hashed_password = make_pw_hash(username, password)

            user = User(
                name=username,
                hashed_password=hashed_password,
                email=email,
                parent=BLOG_KEY
            )
            user.put()

            # set a cookie
            self.set_secure_cookie("user_name", str(user.name))

            # redirect to home page
            self.redirect_to('home')

        else:
            # render the form again, keeping existing input
            self.render(
                'register.html',
                name=username,
                email=email,
                errors=errors,
                user=self.user
            )


class Login(BaseHandler):
    """Handle login requests."""

    def get(self):
        """Render the login form."""
        self.render("login.html", errors=None)

    def post(self):
        """Get data, validate it, login and redirect to the home page."""
        username = self.request.get('name')
        password = self.request.get('password')

        is_valid, errors = validate_login_form(username, password)

        if is_valid:
            # get the user and set a cookie
            user = User.query(User.name == username, ancestor=BLOG_KEY).get()
            self.set_secure_cookie("user_name", str(user.name))

            self.redirect_to('home')

        else:
            # render the form again, keeping existing input
            self.render(
                'login.html',
                name=username,
                errors=errors,
                user=self.user
            )


class Logout(BaseHandler):
    """Handle logout requests."""

    def get(self):
        """Delete existing cookie and redirect to home page."""
        self.clear_cookie()
        self.redirect_to('home')


class Like(BaseHandler):
    """Handle like requests, using json."""

    @login_required_or_redirect
    def post(self):
        """Add or remove a like."""
        post_key_url = self.request.get('post_key_url')
        post = Article.by_key_url(post_key_url)

        # if the current user has already liked the post, he is "unliking"
        if self.user.key in post.liked_by:

            # remove one like
            post.likes -= 1
            is_liked = False

            # remove the user from the list of users who liked the post
            post.liked_by = [
                user_key for user_key in post.liked_by
                if user_key != self.user.key
            ]

            post.put()

            # write the response back in json format. The response is
            # handled by jquery.
            data = json.dumps({
                'likes': post.likes,
                'is_liked': is_liked
            })

            self.response.write(data)

        # the user is liking the post
        else:
            # add one like
            post.likes += 1
            is_liked = True

            # add the user from the list of users who liked the post
            post.liked_by.append(self.user.key)
            post.put()

            # write the response back in json format. The response is
            # handled by jquery.
            data = json.dumps({
                'likes': post.likes,
                'is_liked': is_liked
            })

            self.response.write(data)


#
#
# URL SCHEMA
#
#
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
    webapp2.Route(r'/blog/comment/delete/<comment_key_url:\S+>/<post_key_url:\S+>', handler=DeleteComment, name='delete_comment'),

    webapp2.Route(r'/blog/like', handler=Like, name='like'),
],

    debug=True
)
