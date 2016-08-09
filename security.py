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
import json

from google.appengine.ext import ndb

import jinja2
import webapp2

from models import User, Article, Comment


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
    salt = h.split(',', 1)[1]

    if h == make_pw_hash(name, pw, salt=salt):
        return True
    else:
        return False


#
# Login
#
def login_required(handler_method):
    """..."""
    def check_login(self, *args, **kwargs):
        if not self.user:
            self.response.out.write('test')
            self.redirect_to("login")
            return
        else:
            handler_method(self, *args, **kwargs)
    return check_login



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
        errors["error_author"] = """You must be the original author
        of a post to delete it."""

    if have_error:
        return (False, errors)
    else:
        return (True, None)


def is_author(user, post):
    return user.name == post.author