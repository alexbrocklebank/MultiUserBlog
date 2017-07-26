import os
import hashlib
import hmac
import re
import random
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db

# Secret should be hidden in an external unpublished module
SECRET = 'ljwnehgf.,8734tnfyu7wa3Y^*^&^T#%@#(*&^a4H76R6R[]/6595GFYUJG*^%(G$)'


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def make_secure(s):
    return("{}|{}".format(s, hmac.new(SECRET, s).hexdigest()))


def check_secure(h):
    val = h.split('|')[0]
    if h == make_secure(val):
        return(val)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        # jinja2.Markup()
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '{}={}; Path=/'.format(name, cookie_val)
        )

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=; Path=/'
        )

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.title + '</b><br>')
    response.out.write(post.article)


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in range(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "{},{}".format(salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        return User.all().filter('name = ', name).get()

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = User.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Article(db.Model):
    # Datastore Types:
    # Integer, Float, String, Date, Time, DateTime,
    # Email, Link, PostalAddress, Text
    # String is < 500 chars and indexed
    # Text is > 500 chars and non-indexable
    title = db.StringProperty(required=True)
    article = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class MainPage(Handler):
    def render_home(self):
        articles = db.GqlQuery("SELECT * FROM Article ORDER BY created DESC"
                               " LIMIT 10;")
        # Get Name from Cookie in Headers
        user = self.request.cookies.get('name')
        self.render('index.html', user=user, articles=articles)
        # articles = Article.all().order('-created')

    def get(self):
        self.render_home()


class NewPost(Handler):
    def render_new(self, title="", article="", error=""):
        self.render("newpost.html", title=title, article=article, error=error)

    def get(self):
        # TODO: Check for username exists
        self.render_new()

    def post(self):
        title = self.request.get("subject")
        article = self.request.get("content")
        # TODO: User check

        if title and article:
            # article = article.replace('\n', '<br>')
            a = Article(title=title, article=article)
            # TODO: Insert proper paragraphs?
            a.put()
            postid = a.key().id()
            self.redirect("/blog/posts/{}/".format(postid))
        else:
            error = "You must include both a Title and an Article!\n"
            self.render_new(title, article, error)


class ViewPost(Handler):
    def render_post(self, postid, title="", article="", created=""):
        post = Article.get_by_id(int(postid))
        # key = db.Key.from_path('Article', int(post_id), parent=blog_key())
        # post = db.get(key)
        if not post:
            self.error(404)
            # TODO: make a 404
            return

        self.render("post.html", title=post.title, article=post.article,
                    created=post.created, id=postid)

    def get(self, postid):
        self.render_post(postid)


class Signup(Handler):
    def render_signup(self, username="", password="", verify="", email="",
                      error=""):
        self.render("signup.html", username=username, password=password,
                    verify=verify, email=email, error=error)

    def get(self):
        self.render_signup()

    def post(self):
        # Build variables from Request
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")
        p = hashlib.md5(self.password).hexdigest()

        params = dict(username = self.username,
                      email = self.email,
                      error = "")

        # Password doesn't match Verify
        if not hashlib.md5(self.verify).hexdigest() == p:
            params['error'] += "Passwords don't match!\n"
        # A field is left blank.
        if not (self.username and self.password):
            params['error'] += "You must enter a username and password!\n"
        # No Errors! Move on.
        if params['error'] == "":
            self.done()
            # article = article.content.replace('\n', '<br>')
            # a = Article(title = title, article = article)
            # TODO: Database for Users
            # a.put()
            # postid = a.key().id()
        # Uh Oh! Errors! Re-render page with instructions.
        else:
            self.render_signup(**params)

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # Make sure the User doesn't already exist
        user = User.by_name(self.username)
        if user:
            error = "This user already exists!\n"
            self.render_signup(error=error)
        else:
            user = User.register(self.username, self.password, self.email)
            user.put()

            self.login(user)
            self.redirect('/blog/welcome')


class Login(Handler):
    def render_login(self, username="", error=""):
        self.render('login.html', username=username, error=error)

    def get(self):
        self.render_login()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        error = ""
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/welcome')
        else:
            error = "Invalid User/Password combination.\n"
            self.render_login(username, error)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog/signup')


class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/blog/signup')


app = webapp2.WSGIApplication([('/blog', MainPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Register),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/welcome', Welcome),
                               ('/blog/posts/<postid>/', ViewPost)
                               ],
                              debug=True)
