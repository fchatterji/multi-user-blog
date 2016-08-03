#
# Data model
#

from google.appengine.ext import ndb

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


class Comment(ndb.Model):
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    author = ndb.StructuredProperty(User)
    post = ndb.StructuredProperty(Article)

class Like(ndb.Model):
    number = ndb.IntegerProperty(required=True)
    author = ndb.StructuredProperty(User, required=True)
    post = ndb.StructuredProperty(Article, required=True)