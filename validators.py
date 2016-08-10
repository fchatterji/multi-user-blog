#
#
# Imports
#
#
import re
from auth import check_pw_hash
from models import User, Blog


# blog key needed to make ancestor queries that have strong consistency
BLOG_KEY = Blog.blog_key()


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

    if not user:
        errors['error_username'] = "This username doesn't exist."
        have_error = True

    elif user and not (check_pw_hash(username,
                                     password,
                                     user.hashed_password)):

        errors['error_password'] = "The password is incorrect."
        have_error = True

    elif not valid_username(username):
        errors['error_username'] = "That's not a valid username."
        have_error = True

    if not valid_password(password):
        errors['error_password'] = "That wasn't a valid password."
        have_error = True

    if have_error:
        return (False, errors)
    else:
        return (True, None)
