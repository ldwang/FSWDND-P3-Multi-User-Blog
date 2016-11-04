import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'oEioai$]E38d'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    posted_by = db.ReferenceProperty(User, collection_name="posts" )
    like_count = db.IntegerProperty(default=0)
    dislike_count = db.IntegerProperty(default=0)

    def render(self, user=None):
        self._render_text = self.content.replace('\n', '<br>')
        comments = self.get_comments()
        return render_str("post.html", p = self, user=user, comments=comments)

    def get_comments(self):
        return Comment.all().ancestor(self).order('-last_modified')

    def get_votes(self):
        return Vote.all().filter('post =', self)

class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            error_msg = "This post doesn't exist."
            self.render("error.html", error_msg=error_msg)
            return
        comments = post.get_comments()
        self.render("permalink.html", post = post, comments=comments)

class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                msg = "This post doesn't exist."
                self.render("error.html", error=msg)
                return
            if post.posted_by.name != self.user.name:
                msg = "You are not the author of this post."
                self.render("error.html", error=msg)
                return

            self.render("editpost.html", post=post)

        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                msg = "This post doesn't exist."
                self.render("error.html", error=msg)
                return
            if post.posted_by.name != self.user.name:
                msg = "You are not the creater of this post."
                self.render("error.html", error=msg)
                return

            subject = self.request.get('subject')
            content = self.request.get('content')
            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/blog/%s' % post_id)
            else:
                error = "subject and content, please!"
                self.render("editpost.html", post=post, error=error)
        else:
            self.redirect("/login")

class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                msg = "This post doesn't exist."
                self.render("error.html", error=msg)
                return
            if post.posted_by.name != self.user.name:
                msg = "You are not the author of this post."
                self.render("error.html", error=msg)
                return
            db.delete(post.get_comments())
            db.delete(post.get_votes())
            post.delete()
            self.redirect('/blog')

        else:
            self.redirect("/login")

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')


        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, posted_by=self.user)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

### vote stuff
def vote_key(name = 'default'):
    return db.Key.from_path('votes', name)

class Vote(db.Model):
    voter = db.ReferenceProperty(User)
    post = db.ReferenceProperty(Post)
    like = db.BooleanProperty(required=True)

    @classmethod
    def voted(cls, post, user, like):
        v  = Vote.all().filter('post =', post).filter('like =', like).filter('voter =', user).get()
        #v.filter('like =', like)
        #v.filter('voter =', user).get()
        if v:
            return True
        else:
            return False


class   VotePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                msg = "This post doesn't exist."
                self.render("error.html", error=msg)
                return
            if post.posted_by.name == self.user.name:
                msg = "You are not allowed to vote yourself's post."
                self.render("error.html", error=msg)
                return

            choice = self.request.get('choice')
            if choice not in ['like', 'dislike']:
                msg = "The vote choice is wrong."
                self.render("error.html", error=msg)
                return

            like = True if choice=='like' else False

            if Vote.voted(post, self.user, like):
                msg = "You have voted '%s' before." % choice
                self.render("error.html", error=msg)
                return
            else:
                vote = Vote(parent=vote_key(), voter=self.user, post=post, like=like)
                vote.put()
                if like:
                    post.like_count += 1
                else:
                    post.dislike_count += 1
                post.put()

                self.redirect('/blog/%s' % post_id)

        else:
            self.redirect("/login")


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

#### Comment stuff

class Comment(db.Model):
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    commented_by = db.ReferenceProperty(User, collection_name="comments" )

    def render(self, **parm):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", comment=self, **parm)

class NewComment(BlogHandler):
    def get(self,post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                msg = "This post doesn't exist."
                self.render("error.html", error=msg)
                return
            comments = post.get_comments()
            self.render('permalink.html', post = post, comments=comments)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                msg = "This post doesn't exist."
                self.render("error.html", error=msg)
                return

            content = self.request.get('content')

            if content:
                comment = Comment(parent=post, content=content, commented_by=self.user)
                comment.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                error = "content please!"
                self.render("permalink.html", post=post, error=error)

        else:
            self.redirect("/login")

class DeleteComment(BlogHandler):
    def get(self):
        if self.user:
            post_id = self.request.get('post_id')
            post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(post_key)

            comment_id = self.request.get('comment_id')
            comment_key = db.Key.from_path( 'Comment', int(comment_id), parent=post_key)
            comment = db.get(comment_key)
            if not post:
                msg = "This post  doesn't exist."
                self.render("error.html", error=msg)
                return

            if not comment:
                msg = "This comment doesn't exist."
                self.render("error.html", error=msg)
                return

            if comment.commented_by.name != self.user.name:
                msg = "You are not the author of this comment."
                self.render("error.html", error=msg)
                return

            comment.delete()
            self.redirect('/blog/%s' % str(post.key().id()))

        else:
            self.redirect("/login")

class EditComment(BlogHandler):
    def get(self):
        if self.user:
            post_id = self.request.get('post_id')
            post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(post_key)

            comment_id = self.request.get('comment_id')
            comment_key = db.Key.from_path( 'Comment', int(comment_id), parent=post_key)
            comment = db.get(comment_key)
            if not post:
                msg = "This post  doesn't exist."
                self.render("error.html", error=msg)
                return

            if not comment:
                msg = "This comment doesn't exist."
                self.render("error.html", error=msg)
                return

            if comment.commented_by.name != self.user.name:
                msg = "You are not the author of this comment."
                self.render("error.html", error=msg)
                return

            comments = post.get_comments()
            self.render('editcomment.html', post=post, comment_id=comment_id, content=comment.content, comments=comments)

        else:
            self.redirect("/login")

    def post(self):
        if self.user:
            post_id = self.request.get('post_id')
            post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(post_key)

            comment_id = self.request.get('comment_id')
            comment_key = db.Key.from_path( 'Comment', int(comment_id), parent=post_key)
            comment = db.get(comment_key)
            if not post:
                msg = "This post  doesn't exist."
                self.render("error.html", error=msg)
                return

            if not comment:
                msg = "This comment doesn't exist."
                self.render("error.html", error=msg)
                return

            if comment.commented_by.name != self.user.name:
                msg = "You are not the author of this comment."
                self.render("error.html", error=msg)
                return

            content = self.request.get('content')
            if content:
                comment.content = content
                comment.put()
                self.redirect('/blog/%s' % post_id)
            else:
                error = "content, please!"
                comments = post.get_comments()
                self.render("editcomment.html", post=post,comment_id=comment_id, comments=comments, error=error)


        else:
            self.redirect("/login")

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/vote/([0-9]+)', VotePost),
                               ('/blog/newcomment/([0-9]+)', NewComment),
                               ('/blog/deletecomment', DeleteComment),
                               ('/blog/editcomment', EditComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
