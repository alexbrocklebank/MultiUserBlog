import os
import hashlib
import hmac
import re
import random
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db

# TODO: Clear all TODOs before submission
# TODO: PEP8 Lint before submission

# In actual practice secret should be hidden in an external unpublished module
SECRET = 'ljwnehgf.,8734tnfyu7wa3Y^*^&^T#%@#(*&^a4H76R6R[]/6595GFYUJG*^%(G$)'


jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'),
                               autoescape=True)


# Security functions
def make_secure(s):
    return("{}|{}".format(s, hmac.new(SECRET, s).hexdigest()))


def check_secure(h):
    val = h.split('|')[0]
    if h == make_secure(val):
        return(val)


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


# Webapp2 Handler helper class
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


# Key for Users database
def users_key(group='default'):
    return db.Key.from_path('users', group)


# User database model
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


# Key for Articles table
def articles_key(group='default'):
    return db.Key.from_path('articles', group)


# Articles database model
class Article(db.Model):
    title = db.StringProperty(required=True)
    article = db.TextProperty(required=True)
    creator = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, aid):
        return Article.get_by_id(aid, parent=articles_key())

    @classmethod
    def by_title(cls, title):
        return Article.all().filter('title = ', title).get()


# Key for Comments table
def comments_key(group='default'):
    return db.Key.from_path('comments', group)


# Comments database model
class Comment(db.Model):
    article = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    creator = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# Key for Likes table
def likes_key(group='default'):
    return db.Key.from_path('likes', group)


# Likes database model
class Like(db.Model):
    by_user = db.StringProperty(required=True)
    liked_user = db.StringProperty(required=True)
    article = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# Main Page /blog
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


# Welcome Page /blog/welcome
class Welcome(Handler):
    def get(self):
        if self.user:
            articles = db.GqlQuery("SELECT * FROM Article ORDER BY created "
                                   "DESC LIMIT 10;")
            self.render('welcome.html', username=self.user.name,
                        articles=articles)
        else:
            self.redirect('/blog/signup')


# Signup Page /blog/signup
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

        params = dict(username=self.username,
                      email=self.email,
                      error="")

        # Password doesn't match Verify
        if not hashlib.md5(self.verify).hexdigest() == p:
            params['error'] += "Passwords don't match!\n"
        # A field is left blank.
        if not (self.username and self.password):
            params['error'] += "You must enter a username and password!\n"
        # No Errors! Move on.
        if params['error'] == "":
            self.done()
        # Uh Oh! Errors! Re-render page with instructions.
        else:
            self.render_signup(**params)

    def done(self, *a, **kw):
        raise NotImplementedError


# Registration Page /blog/signup Child Class
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


# Login Page /blog/login
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


# Logout Page /blog/logout
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog/welcome')


# New Post Page /blog/newpost
class NewPost(Handler):
    def render_new(self, title="", article="", error=""):
        self.render("newpost.html", title=title, article=article, error=error)

    def get(self):
        userid = self.read_secure_cookie('user_id')
        user = False

        if userid:
            userid = int(userid)
            user = User.by_id(userid)

        if user:
            self.render_new()
        else:
            self.redirect('/blog/logout')

    def post(self):
        title = self.request.get("subject")
        article = self.request.get("content")
        userid = self.read_secure_cookie('user_id')
        userid = int(userid)
        user = User.by_id(userid)
        creator = ""
        if user:
            creator = user.name
        else:
            error = "Creator not found!\n"
            self.render_new(title, article, error)

        if title and article and creator:
            #article = article.replace('\n', '<br>')
            a = Article(parent=articles_key(), title=title, article=article,
                        creator=creator)
            # TODO: Insert proper paragraphs?
            a.put()
            postid = a.key().id()
            self.redirect("/blog/posts/{}".format(str(postid)))
        else:
            error = "You must include both a Title and an Article!\n"
            self.render_new(title, article, error)


# View Post /blog/post/#
class ViewPost(Handler):
    def render_post(self, postid, user="", post="", content="", error=""):
        comments = db.GqlQuery("SELECT * FROM Comment WHERE article={}"
                               " ORDER BY created ASC;".format(postid))
        likes = db.GqlQuery("SELECT * FROM Like WHERE article={}"
                            " ORDER BY created ASC;".format(postid))
        count = likes.count()
        self.render("post.html", user=user, title=post.title,
                    article=post.article, created=post.created,
                    creator=post.creator, id=postid, likes=count,
                    comments=comments)

    def get(self, postid):
        key = db.Key.from_path('Article', int(postid), parent=articles_key())
        post = db.get(key)
        #post.article = post.article.replace('\n', '<br>')
        userid = self.read_secure_cookie('user_id')
        user = False
        if post:
            if userid:
                userid = int(userid)
                user = User.by_id(userid)

            self.render_post(postid=postid, user=user, post=post,
                             content="", error="")
        else:
            self.error(404)

    def post(self, postid):
        content = self.request.get("content")
        key = db.Key.from_path('Article', int(postid), parent=articles_key())
        post = db.get(key)
        userid = self.read_secure_cookie('user_id')
        user = False
        error = ""

        if userid:
            userid = int(userid)
            user = User.by_id(userid)
        else:
            error += "User does not exist!\n"

        if not post:
            error += "Parent post does not exist!\n"

        if content and user:
            comment = Comment(parent=comments_key(), article=int(postid),
                              content=content, creator=user.name)
            comment.put()
            self.redirect("/blog/posts/{}/comment".format(str(postid)))
        else:
            error += "You must type a comment body!\n"

        self.render_post(postid=postid, user=user, post=post,
                         content=content, error=error)


# Edit Post Page /blog/posts/#/edit
class EditPost(Handler):
    def render_edit(self, postid, title="", article="", error=""):
        self.render("editpost.html", postid=postid, title=title,
                    article=article, error=error)

    def get(self, postid):
        userid = self.read_secure_cookie('user_id')
        user = False
        key = db.Key.from_path('Article', int(postid), parent=articles_key())
        post = db.get(key)

        if userid:
            userid = int(userid)
            user = User.by_id(userid)

        if user and post:
            self.render_edit(postid=postid, title=post.title,
                             article=post.article, error="")
        else:
            self.redirect("/blog/posts/{}".format(str(postid)))

    def post(self, postid):
        key = db.Key.from_path('Article', int(postid), parent=articles_key())
        post = db.get(key)
        title = self.request.get("subject")
        article = self.request.get("content")

        if title and article:
            # article = article.replace('\n', '<br>')
            post.title = title
            post.article = article
            # TODO: Insert proper paragraphs?
            post.put()
            self.redirect("/blog/posts/{}".format(str(postid)))
        else:
            error = "You must include both a Title and an Article!\n"
            self.render_edit(postid=postid, title=title,
                             article=article, error=error)


# Delete Post Page /blog/posts/#/delete
class DeletePost(Handler):
    def get(self, postid):
        self.render("deletepost.html")

    def post(self, postid):
        delete = self.request.get("delete")
        if delete == "yes":
            key = db.Key.from_path('Article', int(postid),
                                   parent=articles_key())
            post = db.get(key)
            post.delete()
            self.render('deletesuccess.html')
        else:
            self.redirect("/blog/posts/{}/edit".format(str(postid)))


# Like Post Page /blog/posts/#/like
class LikePost(Handler):
    def get(self, postid):
        key = db.Key.from_path('Article', int(postid), parent=articles_key())
        post = db.get(key)
        userid = self.read_secure_cookie('user_id')
        user = False
        if userid:
            userid = int(userid)
            user = User.by_id(userid)

        if user and post:
            if user.name != post.creator:
                likes = db.GqlQuery("SELECT * FROM Like WHERE article={} and"
                                    " by_user='{}' ORDER BY created ASC"
                                    ";".format(postid, user.name))
                count = likes.count()
                if count < 1:
                    like = Like(parent=likes_key(), by_user=user.name,
                                liked_user=post.creator, article=int(postid))
                    like.put()
                    self.render('likesuccess.html', postid=postid,
                                success=True)
                else:
                    self.render('likesuccess.html', postid=postid,
                                success=False)
            else:
                self.redirect("/blog/posts/{}".format(str(postid)))
        else:
            self.redirect("/blog/posts/{}".format(str(postid)))


# Comment Post Page /blog/posts/#/comment
class CommentPost(Handler):
    def get(self, postid):
        self.render('comment.html', postid=postid, success=True)


# Edit Comment Page /blog/posts/#/comment/#/edit
class EditComment(Handler):
    def render_edit(self, postid, commentid, comment, error=""):
        self.render('editcomment.html', postid=postid, commentid=commentid,
                    comment=comment, error=error)

    def get(self, postid, commentid):
        userid = self.read_secure_cookie('user_id')
        user = False
        key = db.Key.from_path('Comment', int(commentid), parent=comments_key())
        comment = db.get(key)

        if userid:
            userid = int(userid)
            user = User.by_id(userid)

        if user and comment:
            self.render_edit(postid=postid, comment=comment,
                             commentid=commentid,  error="")
        else:
            self.redirect("/blog/posts/{}".format(str(postid)))
        # TODO: Implement logic to edit Comment by Creator

    def post(self, postid, commentid):
        key = db.Key.from_path('Comment', int(commentid), parent=comments_key())
        comment = db.get(key)
        content = self.request.get("content")

        if content:
            comment.content = content
            comment.put()
            # TODO: Create an all-in-one successpage that redirects
            # to the next page after 5 seconds to allow database to updateself.
            # Pass in redirect-to URL and the success message.
            self.redirect("/blog/posts/{}".format(str(postid)))
        else:
            error = "You must include content for your comment!\n"
            self.render_edit(postid=postid, commentid=commentid,
                             comment=comment, error=error)


# Delete Comment Page /blog/posts/#/comment/#/delete
class DeleteComment(Handler):
    def get(self, postid, commentid):
        self.render('deletecomment.html', postid=postid, commentid=commentid)

    def post(self, postid, commentid):
        delete = self.request.get("delete")
        if delete == "yes":
            key = db.Key.from_path('Comment', int(commentid),
                                   parent=comments_key())
            comment = db.get(key)
            comment.delete()
            self.render('deletesuccess.html')
        else:
            self.redirect("/blog/posts/{}/comment/{}/edit".format(str(postid),
                          str(commentid)))
    # TODO: Test Me
    # Something funky is going on here...

# URL Routing
app = webapp2.WSGIApplication([('/blog', MainPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Register),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/welcome', Welcome),
                               ('/blog/posts/([0-9]+)', ViewPost),
                               ('/blog/posts/([0-9]+)/edit', EditPost),
                               ('/blog/posts/([0-9]+)/delete', DeletePost),
                               ('/blog/posts/([0-9]+)/like', LikePost),
                               ('/blog/posts/([0-9]+)/comment', CommentPost),
                               ('/blog/posts/([0-9]+)/comment/([0-9]+)/edit',
                                EditComment),
                               ('/blog/posts/([0-9]+)/comment/([0-9]+)/delete',
                                DeleteComment)
                               ],
                              debug=True)
