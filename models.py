#
# Data model
#

from google.appengine.ext import ndb

class User(ndb.Model):

    name = ndb.StringProperty(required=True)
    hashed_password = ndb.StringProperty(required=True)
    email = ndb.StringProperty()


class Comment(ndb.Model):
    content = ndb.TextProperty(required=True)
    author = ndb.StructuredProperty(User)

    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)


class Article(ndb.Model):
    """Article model, represents a blog post."""

    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    author = ndb.StructuredProperty(User)

    likes = ndb.IntegerProperty(required=True, default=0)
    liked_by = ndb.KeyProperty(User, repeated=True)

    comments = ndb.StructuredProperty(Comment, repeated=True)

    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)




class Blog(ndb.Model):
    name = ndb.StringProperty(required=True)