#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
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
import webapp2
import os
import re
import jinja2
import hashlib
import random

from string import letters
from google.appengine.ext import db

loader = jinja2.FileSystemLoader(
    os.path.join(
        os.path.dirname(__file__),
        'templates'))
jinja_environment = jinja2.Environment(
    autoescape=True,
    extensions=["jinja2.ext.do"],
    loader=loader)


class Parent(webapp2.RequestHandler):

    def write(self, template_name, **params):
        template = jinja_environment.get_template(template_name)
        self.response.write(template.render(**params))


# from my Udacity instructor
def render_str(template, **params):
    t = jinja_environment.get_template(template)
    return t.render(params)


# Creating the tables...
class Post(db.Model, Parent):
    subject = db.StringProperty()
    content = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty()
    post_author_name = db.StringProperty()
    post_author_id = db.StringProperty()

    def render_post_template(self, user_id=None):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self, user_id=user_id)

    def render_post_comment(self, user_id=None):
        return render_str("post-comment.html", p=self, user_id=user_id)

    def compare_like_author_to_user(self, user_id):
        disable_like_button = ''
        for like in self.like:
            if like.like_author == user_id:
                disable_like_button = 'disabled'
        return disable_like_button


class UserTable(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)


class Likes(db.Model):
    post_id = db.ReferenceProperty(Post, collection_name='like')
    like_author = db.StringProperty()


class Comment(db.Model):
    content = db.StringProperty(required=True)
    date = db.DateTimeProperty(auto_now=True)
    post_id = db.ReferenceProperty(Post, collection_name='comment')
    comment_author_name = db.StringProperty()
    comment_author_id = db.StringProperty()


# Handling requests...
class HomeHandler(Parent):
    '''renders home page with name if logged in'''

    def get(self):
        cookie_value = UserCookie().cookie_value(self.request)
        params = {}

        if not cookie_value:
            params['logged_in'] = False
        else:
            params['logged_in'] = True
            username = UserCookie().username(self.request)
            params['name'] = username

        self.write(template_name='home_page.html', **params)


class Signup(Parent):

    def get(self):
        self.write(template_name='signup.html')


class Login(Parent):

    def get(self):
        self.write(template_name='login.html')


class LogoutHandler(Parent):
    '''clears cookie and renders login.html'''

    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=')
        self.redirect('/login')


class Welcome(Parent):
    '''renders welcome page with user name'''

    def get(self, **params):
        cookie_value = UserCookie().cookie_value(self.request)
        if not cookie_value:
            self.redirect('/login')
        else:
            username = UserCookie().username(self.request)
            params['name'] = username
            self.write(template_name='welcomepage.html', **params)


class CookieSetter(Parent):

    def set_cookie(self, username, password, salt, response):
        hashed_pass = PwdHasher().hash_password(username, password, salt)
        response.headers.add_header(
            'Set-Cookie', 'username=%s|%s; Path=/' %
            (str(username), str(hashed_pass)))


class UserCookie():

    def cookie_value(self, request):
        return request.cookies.get('username')

    def username(self, request):
        return self.cookie_value(request).split('|')[0]

    def ID_of_user(self, request):
        username = self.username(request)
        get_user = UserTable.all().filter('username =', username).get()
        user_id = get_user.key()
        return str(user_id)

# I got the regex code from my Udacity instructor.
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


class PwdHasher():

    def make_salt(self, length=5):
        return ''.join(random.choice(letters) for x in xrange(length))

    def hash_password(self, name, pwd, salt=None):
        if not salt:
            salt = self.make_salt()
        hashed_password = hashlib.sha256(name + pwd + salt).hexdigest()
        return "%s,%s" % (hashed_password, salt)


class SignupHandler(Parent, db.Model):
    '''handles input from signup.html'''

    def is_valid(self, username, password, verify, email, params):

        if not valid_username(username):
            params['valid_name'] = 'Please enter a valid name'
            return False, params

        if not valid_password(password):
            params['valid_password'] = 'Please enter a valid password'
            return False, params

        elif password != verify:
            params['redo_password'] = "Your passwords don't match."
            return False, params

        return True, params

    def is_already_user(self, username):
        return UserTable.all().filter('username =', username).get()

    def handle_user_already_exists(self):
        self.redirect('/login')

    def handle_new_user(self, params, username, password):
        self.redirect('/welcome')
        hashed_pass = PwdHasher().hash_password(username, password)
        user = UserTable(username=username, password=hashed_pass)
        user.put()
        # double put as a workaround Google Datastore's latency
        user.put()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = {'name': username, 'email': email}
        signup_form_valid = True

        signup_form_valid, params = self.is_valid(
            username, password, verify, email, params)

        if not signup_form_valid:
            self.write(template_name='signup.html', **params)
        elif self.is_already_user(username):
            self.handle_user_already_exists()
        else:
            self.handle_new_user(params, username, password)
            user_lookup = UserTable.all().filter('username =', username).get()
            hashed_password = user_lookup.password
            salt = hashed_password.split(',')[1]
            cookie = CookieSetter().set_cookie(username,
                                               password, salt, self.response)


class LoginHandler(Parent, db.Model):
    '''handles input from login.html'''

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        if username and password:
            user = UserTable.all().filter('username =', username).get()
            if user:
                hashed_password = user.password
                salt = hashed_password.split(',')[1]

                if hashed_password == PwdHasher().hash_password(
                        username, password, salt):
                    set_cookie = CookieSetter().set_cookie(
                        username, password, salt, self.response)
                    self.redirect('/welcome')
                else:
                    self.write(
                        'login.html',
                        name=username,
                        valid_password='Invalid password!')
            else:
                self.redirect('/signup')
        else:
            if not username:
                self.write(
                    'login.html',
                    password=password,
                    valid_name='please include your username')
            if not password:
                self.write(
                    'login.html',
                    name=username,
                    valid_password='please include your password')


class BlogFront(Parent):
    '''renders fron page with top posts, comments, and buttons'''

    def top_posts(self):
        return db.GqlQuery("select * from Post order by created desc limit 10")

    def is_valid_user(self):
        cookie_value = UserCookie().cookie_value(self.request)
        if cookie_value:
            username = UserCookie().username(self.request)
            user = UserTable.all().filter('username =', username).get()
            if user:
                return True

    def get(self):
        cookie_value = UserCookie().cookie_value(self.request)
        if cookie_value:
            user_id = UserCookie().ID_of_user(self.request)
            self.write(
                'front.html',
                posts=self.top_posts(),
                user_id=user_id,
                cookie_value=cookie_value)
        else:
            self.write(
                'front.html',
                posts=self.top_posts(),
                cookie_value=cookie_value)

    def post(self):
        if not self.is_valid_user():
            self.redirect('/login')
            return

        post_id = self.request.get('post_id')
        user_id = UserCookie().ID_of_user(self.request)

        if post_id:  # has value if button clicked in front.html
            post = db.get(db.Key(post_id))
            # if no value found for post ID
            if not post:
                self.error(401)
                self.write('error.html')
                return

            is_user_the_author = post.post_author_id == user_id

            like_button = self.request.get('like_button')
            unlike_button = self.request.get('unlike_button')
            comment_button = self.request.get('comment_button')
            edit_button = self.request.get('edit_button')
            delete_button = self.request.get('delete_button')

            if edit_button or delete_button:
                if not is_user_the_author:
                    # user unauthorized to make changes to post
                    self.error(401)
                    self.write('error.html')
                    return

                if edit_button:
                    # render newpost.html as an edit form
                    params = {}
                    params['heading'] = 'edit'
                    params['subject'] = post.subject
                    params['content'] = post.content
                    params['post_id'] = post_id
                    params['handler'] = '/blog/edit'
                    params['post_url_number'] = post.key().id()
                    self.write('newpost.html', **params)

                if delete_button:
                    post.delete()
                    # double 'delete' to workaround Google Datastore's latency
                    post.delete()
                    self.redirect('/blog')

            if like_button or unlike_button or comment_button:
                user_id = UserCookie().ID_of_user(self.request)
                if is_user_the_author:
                    # user unauthorized to do these actions
                    self.response.http_status_message(401)
                    self.write('error.html')
                    return

                if like_button:
                    like_author = user_id
                    l = Likes(
                        post_id=post, like_author=like_author)
                    l.put()
                    # double put as a workaround Google Datastore's latency
                    l.put()
                    post.likes += 1
                    post.put()
                    # double put as a workaround Google Datastore's latency
                    post.put()
                    self.redirect('/blog')

                if unlike_button:
                    like_author = user_id
                    l = Likes(
                        post_id=post, like_author=like_author)
                    l.put()
                    # double put as a workaround Google Datastore's latency
                    l.put()
                    post.likes -= 1
                    post.put()
                    # double put as a workaround Google Datastore's latency
                    post.put()
                    self.redirect('/blog')

                if comment_button:
                    self.write(
                        'comment.html',
                        post=post,
                        post_id=post_id)


# I got this class from my Udacity instructor
class PostPage(Parent):
    '''renders unique post upon creation'''

    def get(self, post_id):
        post_key = db.Key.from_path('Post', int(post_id))
        post = db.get(post_key)
        self.write("permalink.html", post=post)


class NewPost(Parent):
    '''handles new post submitted via post form in newpost.html'''

    def get(self):
        cookie_val = UserCookie().cookie_value(self.request)

        if not cookie_val:
            self.redirect('/login')
        else:
            name = UserCookie().username(self.request)
            self.write("newpost.html")

    def post(self):
        cancel = self.request.get('cancel')
        if cancel:
            self.redirect('/blog')
            return
        try:
            username = UserCookie().username(self.request)
            user_id = UserCookie().ID_of_user(self.request)
        except AttributeError:
            # invalid user on not signed in
            self.error(401)
            self.write('error.html')
        else:
            # create Post object using form fields
            subject = self.request.get('subject')
            content = self.request.get('content')
            likes = 0

            if subject and content:
                p = Post(
                    subject=subject,
                    content=content,
                    likes=likes,
                    post_author_name=username,
                    post_author_id=user_id)
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = "subject and content, please!"
                self.write(
                    "newpost.html",
                    subject=subject,
                    content=content,
                    error=error)


class EditPost(Parent):
    '''handles a post edit submitted via post form in newpost.html'''

    def post(self):
        post_id = self.request.get('post_id')
        post_url_number = self.request.get('post_url_number')

        try:
            user_id = UserCookie().ID_of_user(self.request)
            specific_post_object = db.get(db.Key(post_id))
            if specific_post_object.post_author_id != user_id:
                raise AttributeError
        except AttributeError:
            # user not found, post not found, user unauthorized to edit post
            self.error(401)
            self.write('error.html')
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')

            specific_post_object.subject = subject
            specific_post_object.content = content
            specific_post_object.put()
            # double put as a workaround Google Datastore's latency
            specific_post_object.put()
            self.redirect('/blog/%s' % str(post_url_number))


class CommentPost(Parent):
    '''handles content of comment or comment-edit'''

    def post(self):
        content = self.request.get('content')
        post_id = self.request.get('post_id')
        comment_id = self.request.get('comment_id')
        delete_button = self.request.get('delete_button')
        if not content:
            error = 'Wait! We want that comment!!!'
            self.write('comment.html', post=post, post_id=post_id, error=error)
            return
        try:
            post = db.get(db.Key(post_id))
            user_id = UserCookie().ID_of_user(self.request)
            if user_id == post.post_author_id:
                raise AttributeError
        except AttributeError:
            # post or user not found or user unauthorized to write comment
            self.error(401)
            self.write('error.html')
        else:
            if comment_id:  # handles the instance of a comment-edit
                try:
                    comment = db.get(db.Key(comment_id))
                    if comment.comment_author_id != user_id:
                        raise AttributeError
                except AttributeError:
                    # comment doesn't exist or user unauthorize to edit comment
                    self.error(401)
                    self.write('error.html')
                else:
                    if delete_button:
                        comment.delete()
                        # double delete to workaround Google Datastore latency
                        comment.delete()
                    else:
                        comment.content = content
                        comment.put()
                        # double put as a workaround Google Datastore's latency
                        comment.put()
                    self.redirect('/blog')
            else:  # handles a new comment
                post = db.get(db.Key(post_id))
                username = UserCookie().username(self.request)
                user_id = UserCookie().ID_of_user(self.request)
                comment = Comment(
                    content=content,
                    post_id=post,
                    comment_author_id=str(user_id),
                    comment_author_name=username)
                comment.put()
                # double put as a workaround Google Datastore's latency
                comment.put()
                self.redirect('/blog')


class EditComment(Parent):
    '''renders comment form when author clicks on comment to edit'''

    def post(self):
        params = {}
        post_id = self.request.get('post_id')
        comment_id = self.request.get('comment_id')
        params['post_id'] = post_id
        params['comment_id'] = comment_id
        lookup_post = db.Key(post_id)
        params['post'] = db.get(lookup_post)
        lookup_comment = db.Key(comment_id)
        comment = db.get(lookup_comment)
        params['content'] = comment.content
        params['edit'] = 'edit'

        self.write('comment.html', **params)


app = webapp2.WSGIApplication([
    ('/', HomeHandler),
    ('/signup', Signup),
    ('/signup/handle', SignupHandler),
    ('/login', Login),
    ('/login/handle', LoginHandler),
    ('/welcome', Welcome),
    ('/logout', LogoutHandler),
    ('/blog', BlogFront),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/blog/edit', EditPost),
    ('/blog/comment', CommentPost),
    ('/blog/comment/edit', EditComment)
], debug=True)
