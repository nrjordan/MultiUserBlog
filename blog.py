"""This python file is to be used in Google App Engine along with
HTML templates to create a multi-user blog.
Author: Nick Jordan
Date: 3/29/2017"""


import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
                               autoescape=True)

SECRET = 'jargonandstuff'

def render_str(template, **params):
    """Render the HTML strings"""
    t = JINJA_ENV.get_template(template)
    return t.render(params)

def make_secure_val(val):
    """Create a secure value"""
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    """Check secure value"""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    """Main class for blog actions"""
    def write(self, *a, **kw):
        """Create the blog"""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """Render with given parameters"""
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        """Render the template with given parameters"""
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """Create a cookie for the user"""
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Check the user's cookie"""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """Log a user in by giving them a cookie"""
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """Log a user out by giving them a blank cookie"""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """Store cookie in user object"""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    """Render a post"""
    response.out.write('<a href="/blog/%s>"<b>' %post.id + post.subject + '</b></a><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
    """This handles the main page of the site -- simply a link to the blog"""
    def get(self):
        """Get method for main page, giving user link to blog"""
        self.write('You probably wanted to go <a href="/blog/"> here</a>!')

##### user stuff
def make_salt(length=5):
    """Create salt"""
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    """Create hash"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    """Validate the password"""
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group='default'):
    """Determine key based on user"""
    return db.Key.from_path('users', group)

class User(db.Model):
    """This table defines the User object"""
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """Get a user object from an ID"""
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        """Get a user object from a username"""
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        """Register a new user object"""
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name='default'):
    """Store key information"""
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    """Create the post object"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True)
    liked_by = db.ListProperty(str)

    def check_ownership(self, user):
        """Check to make sure current user is owner of post"""
        return str(self.created_by) == str(user)

    def render(self):
        """Render post"""
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p=self)

class BlogFront(BlogHandler):
    """Create the blog's front page"""
    def get(self):
        """Get information for front page"""
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)

class PostPage(BlogHandler):
    """Create a page for a specific post"""
    def get(self, post_id):
        """Get information for a post page"""
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comment = db.GqlQuery("SELECT * FROM Comments WHERE post_id =:1", str(post_id))

        if not post:
            self.error(404)
            return

        self.render('permalink.html', post=post, comment=comment)

    def post(self, post_id):
        """Add or remove your like from a post if you're not post owner"""
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user:
            user = self.user.name
            comment = db.GqlQuery("SELECT * FROM Comments WHERE post_id =:1", str(post_id))
            likedlist = post.liked_by
            if user != post.created_by:
                if user in post.liked_by:
                    likedlist.remove(user)
                    post.likes -= 1
                    post.put()
                    self.render('permalink.html', post=post, comment=comment)
                else:
                    likedlist.append(user)
                    post.likes += 1
                    post.put()
                    self.render('permalink.html', post=post, comment=comment)
            else:
                self.render('permalink.html', post=post, comment=comment,
                            likeerror="You can't like your own post!")
        else:
            self.render('error.html', error="You need to be logged in to do that.")

class NewPost(BlogHandler):
    """Create a new Post object"""
    def get(self):
        """Give user login page or new post page"""
        if self.user:
            self.render('newpost.html')
        else:
            self.render('error.html', error="You need to be logged in to do that.")

    def post(self):
        """Create a new Post object from the parameters given by user"""
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        userid = self.user.name

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, created_by=userid, likes=0)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'We need both a subject and some content!'
            self.render('newpost.html', subject=subject, content=content, error=error)


class EditPost(BlogHandler):
    """Edit an already created post object if user is owner"""
    def get(self, post_id):
        """Show edit page if user has permissions"""
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if self.user.name == post.created_by:
                self.render('editpost.html', post=post, content=post.content, subject=post.subject)
            else:
                self.render('error.html', error="You can't edit someone else's post!")
        else:
            self.render('error.html', error="You need to be logged in to do that.")


    def post(self, post_id):
        """Post the edit based on parameters received from user"""
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            posts = db.get(key)
            posts.content = self.request.get('content')
            posts.subject = self.request.get('subject')
            posts.put()
            posts = Post.all().order('-created')
            self.redirect('/blog')
#            self.render('front.html', posts = posts)
#            self.render('front.html', posts=posts)
        else:
            self.redirect('/login')

class DeletePost(BlogHandler):
    """Delete a post object if user is owner"""
    def post(self, post_id):
        """Delete the post object and redirect to front page"""
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        post.delete()
        self.redirect('/blog')

    def get(self, post_id):
        """Show the user an error if not owner of page, otherwise confirm deletion"""
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if self.user.name == post.created_by:
                self.render('deletepost.html', post=post)
            else:
                self.render('error.html', error="You can't delete someone else's post!")
        else:
            self.render('error.html', error="You need to be logged in to do that.")

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    """Check validity of new username"""
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    """Check validity of new password"""
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    """Check validity of new email"""
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    """Create the signup form"""
    def get(self):
        """Render the form"""
        self.render('signup-form.html')

    def post(self):
        """Submit form and create account if parameters are valid"""
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

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
    """Allow user to create new account"""
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    """Allow user to log into site"""
    def get(self):
        """Render login form"""
        self.render('login-form.html')

    def post(self):
        """Check credentials and log user in"""
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)

class Logout(BlogHandler):
    """Allow user to log out of website"""
    def get(self):
        """Log user out and redirect to blog's front page"""
        self.logout()
        self.redirect('/blog')


class Welcome(BlogHandler):
    """Welcome user to the site"""
    def get(self):
        """Render welcome page or redirect to signup"""
        username = self.user.name
        if valid_username(username):
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')

class Comments(db.Model):
    """Create a comment object"""
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)

    def check_ownership(self, user):
        """Check current user's ownership of comment"""
        return str(self.created_by) == str(user)

    def render(self):
        """Render comment"""
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p=self)

class PostComment(BlogHandler):
    """Create a new comment"""
    def get(self, post_id):
        """Redirect user to login page if not already logged in"""
        if self.user:
            self.render('postcomment.html')
        else:
            self.redirect('/login')

    def post(self, post_id):
        """Allows user to post comment if logged in"""
        if not self.user:
            self.redirect('/blog')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        content = self.request.get('content')
        userid = self.user.name
        c = Comments(parent=blog_key(), content=content, created_by=userid, post_id=post_id)
        c.put()
        self.redirect('/blog/%s' % str(post.key().id()))

class EditComment(BlogHandler):
    """Allow user to edit comments they own"""
    def get(self, post_id, comment_id):
        """Render comment data to edit"""
        key = db.Key.from_path('Comments', int(comment_id), parent=blog_key())
        comment = db.get(key)
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        if self.user:
            if self.user.name == comment.created_by:
                self.render('editcomment.html', content=comment.content)
            else:
                comment = db.GqlQuery("SELECT * FROM Comments WHERE post_id =:1", str(post_id))
                self.render('error.html', error="You can't edit someone else's comment!")
        else:
            self.render('error.html', error="You need to be logged in to do that.")


    def post(self, post_id, comment_id):
        """Post updated comment content"""
        if self.user:
            key = db.Key.from_path('Comments', int(comment_id), parent=blog_key())
            comment = db.get(key)
            postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(postkey)
            comment.content = self.request.get('content')
            comment.put()
            comment = db.GqlQuery("SELECT * FROM Comments WHERE post_id =:1", str(post_id))
            self.render('permalink.html', post=post, comment=comment)

        else:
            comment = db.GqlQuery("SELECT * FROM Comments WHERE post_id =:1", str(post_id))
            self.render('permalink.html', post=post, comment=comment,
                        commenterror="You can't edit someone else's comment!")

class DeleteComment(BlogHandler):
    """Allow user to delete comments they no longer want"""
    def post(self, post_id, comment_id):
        """Delete a comment"""
        key = db.Key.from_path('Comments', int(comment_id), parent=blog_key())
        comment = db.get(key)
        comment.delete()
        self.redirect('/blog')

    def get(self, post_id, comment_id):
        """Render comment deletion page"""
        key = db.Key.from_path('Comments', int(comment_id), parent=blog_key())
        comment = db.get(key)
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        if self.user:
            if self.user.name == comment.created_by:
                self.render('deletecomment.html', comment=comment)
            else:
                comment = db.GqlQuery("SELECT * FROM Comments WHERE post_id =:1", str(post_id))
                self.render('error.html', error="You can't delete someone else's comment!")
        else:
            self.render('error.html', error="You need to be logged in to do that.")


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/([0-9]+)/edit', EditPost),
                               ('/blog/([0-9]+)/delete', DeletePost),
                               ('/blog/([0-9]+)/comment', PostComment),
                               ('/blog/([0-9]+)/([0-9]+)/edit', EditComment),
                               ('/blog/([0-9]+)/([0-9]+)/delete', DeleteComment),
                              ],
                              debug=True)
