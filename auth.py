#
#
# Imports
#
#
import hmac
import string
import hashlib
import random

from models import Article, Comment


#
#
# Constants
#
#
""" secret key used to hash cookies. This should be
hidden in production code."""
SECRET = 'secret'


#
#
# Security functions
#
#
def hash_str(s):
    """Return a hash of a string, with the hmac algorithm."""
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    """Return a string and it's hashed value, separated by a comma."""
    return "%s,%s" % (s, hash_str(s))


def check_secure_val(h):
    """Check if a hash is valid."""
    h = h.split(',', 1)

    return h[0] if hash_str(h[0]) == h[1] else None


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

    return True if h == make_pw_hash(name, pw, salt=salt) else False


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
