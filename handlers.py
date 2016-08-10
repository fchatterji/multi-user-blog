#
#
# IMPORTS
#
#
import os
import logging
import json

from google.appengine.ext import ndb

import jinja2
import webapp2

from models import User, Article, Comment, Blog

from auth import(
    login_required_or_redirect,
    article_author_required_or_redirect,
    comment_author_required_or_redirect
)

from auth import make_pw_hash, make_secure_val

from validators import(
    validate_signup_form,
    validate_login_form,
    validate_create_post_form,
    validate_update_post_form
)


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


# blog key needed to make ancestor queries that have strong consistency
BLOG_KEY = Blog.blog_key()


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
        q = Article.query(ancestor=BLOG_KEY).order(-Article.created)
        posts = q.fetch()

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
