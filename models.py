from google.appengine.ext import ndb


class User(ndb.Model):
    """A user, only a hashed password is stored."""

    name = ndb.StringProperty(required=True)
    hashed_password = ndb.StringProperty(required=True)
    email = ndb.StringProperty()


class Comment(ndb.Model):
    """A comment."""

    content = ndb.TextProperty(required=True)
    author = ndb.StructuredProperty(User)

    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)

    @classmethod
    def by_key_url(cls, key_url):
        """Return a comment based on a key url."""
        comment_key = ndb.Key(urlsafe=key_url)
        comment = comment_key.get()
        return comment


class Article(ndb.Model):
    """Article model, represents a blog post."""

    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    author = ndb.StructuredProperty(User)

    likes = ndb.IntegerProperty(required=True, default=0)
    liked_by = ndb.KeyProperty(User, repeated=True)

    comments = ndb.KeyProperty(Comment, repeated=True)

    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)

    @classmethod
    def by_key_url(cls, key_url):
        """Return a post based on a key url."""
        post_key = ndb.Key(urlsafe=key_url)
        post = post_key.get()
        return post


class Blog(ndb.Model):
    """
    Model used as an ancestor to all other models.

    It is used to ensure strong consistency when making queries.
    """

    name = ndb.StringProperty(required=True)
