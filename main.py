#!/usr/bin/env python
# -*- coding: utf-8 -*-


#
#
# Imports
#
#
import webapp2

from handlers import(
    Home,
    Register,
    Login,
    Logout,
    CreatePost,
    UpdatePost,
    DeletePost,
    CreateComment,
    UpdateComment,
    DeleteComment,
    Like
)


#
#
# URL SCHEMA
#
#
app = webapp2.WSGIApplication([

    webapp2.Route(r'/', handler=Home, name='home'),
    webapp2.Route(r'/blog', handler=Home, name='home'),

    webapp2.Route(r'/blog/register', handler=Register, name='register'),
    webapp2.Route(r'/blog/login', handler=Login, name='login'),
    webapp2.Route(r'/blog/logout', handler=Logout, name='logout'),

    webapp2.Route(r'/blog/create',
                  handler=CreatePost, name='create_post'),

    webapp2.Route(r'/blog/update/<post_key_url:\S+>',
                  handler=UpdatePost, name='update_post'),

    webapp2.Route(r'/blog/delete/<post_key_url:\S+>',
                  handler=DeletePost, name='delete_post'),

    webapp2.Route(r'/blog/comment/create/<post_key_url:\S+>',
                  handler=CreateComment, name='create_comment'),

    webapp2.Route(r'/blog/comment/update/<comment_key_url:\S+>',
                  handler=UpdateComment, name='update_comment'),

    webapp2.Route(
        r'/blog/comment/delete/<comment_key_url:\S+>/<post_key_url:\S+>',
        handler=DeleteComment,
        name='delete_comment'
    ),

    webapp2.Route(r'/blog/like', handler=Like, name='like'),
],

    debug=True
)
