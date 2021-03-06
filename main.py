import os

import re
from string import letters
import webapp2
import jinja2
import random
import hashlib
import hmac

from google.appengine.ext import db
# all the above needed in support of program

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'im not telling'


def render_str(template, **params):
    # unclear why this is here.  Not in video
    t = jinja_env.get_template(template)
    # but wont work without it.
    return t.render(params)


def make_secure_val(val):
    # returns secure val with hashed secret
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    # validates secure value with secret
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    # 3 things which are copied

    def write(self, *a, **kw):
        # writes to client browser
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        # this makes it easier for instructor
        params['user'] = self.user
        # renders html.  Still trying to understand
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):  # makes a cookie
        cookie_val = make_secure_val(val)  # cookie name=name and value=val
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
        # no exp. so exp when browser closed

    def read_secure_cookie(self, name):  # rerturns cookie value
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):  # validates user
        self.set_secure_cookie('user_id', str(user.key().id()))
        # sets the cookie using user id and thats how we get the user id in the
        # db

    def logout(self):  # clears login info and clears cookie
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        # checks to see if cookie 'uid' exists and if so, stores in self.user


def render_post(response, post):
    # this is to allow for line breaks
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):  # this is main page of url

    def get(self):
        self.write("Welcome to Ken's Blog.")
        self.write(
            "  This was the most difficult (aka frustrating)\
             assignment yet!<br>")
        self.write("In order to navigate my blog, ")
        self.write("click on the link below to get to the main page.<br><br>")
        self.write(
            "From there, you may navigate to the SIGNUP PAGE, LOGIN PAGE<br>")
        self.write("or any other page of your choosing.  Enjoy.<br><br>")
        self.write(
            "'/blog' will take you to the main page")
        self.write(" or you can click below.<br><br>")
        blog1 = ("Blog Page <a href=/blog>Click here to get to Ken's Blog")
        self.write(blog1)


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)  # we store h in db


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)
    # checks name and pw and compares against value in db


def users_key(group='default'):  # this is for our parent relationship
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)  # stores hashed pw
    email = db.StringProperty()

    @classmethod  # call by using 'get_by_id'
    def by_id(cls, uid):  # cls refers to self
        # return User.get_by_id(uid, parent = users_key())
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        #u = User.all().filter('name =', name).get()
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod  # makes pw hash
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(), name=name, pw_hash=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u  # returns user if name and pw valid.  None if not


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)  # sets stage for multiple blogs


class Post(db.Model):
    # look up StringProperty, TextProperty, etc
    subject = db.StringProperty(required=True)
    # text property can be greater than 500 characters
    content = db.TextProperty(required=True)
    # string property can be indexed but text property cannot
    # auto_now_add is a time stamp
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(
        auto_now=True)  # lists time last updated
    created_by = db.TextProperty()
    user_id = db.IntegerProperty(required=True)  # needed to identify user
    likes = db.IntegerProperty(required=True)
    liked_by = db.ListProperty(str)

    @classmethod
    def by_post_name(cls, name):
        # select * from User where name = name
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def by_name(cls, name):
        u = db.GqlQuery("select * from User where name=name")
        # same as above line....u = cls.all().filter('name =', name).get()
        return u

    def render(self):  # renders blog entry
        # inputs new lines for html line breaks
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))


# these return True or False based on user input
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")  # validates username


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
# validates PW


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
# validates email


def valid_email(email):
    return not email or EMAIL_RE.match(email)
    # the OR in the above allows for the email to be optional


class Signup(BlogHandler):

    def get(self):
        return self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        # creates dictionary of invalid username&emails
        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "Invalid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Invalid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Password mismatch."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Invalid email."
            have_error = True

        if have_error:
            return self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):  # inherits from Signup Class

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'Duplicate user exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()  # this command stores u in database

            self.login(u)
            return self.redirect('/unit3/welcome')


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        # returns user if username and pw valid
        u = User.login(username, password)
        if u:
            # this login is from BlogHandler Class which sets the cookie using
            # u which is returned from login(username, password)
            self.login(u)
            return self.redirect('/blog')
        else:
            msg = 'Invalid login'
            return self.render('login-form.html', error=msg)


class BlogFront(BlogHandler):

    def get(self):
        username = self.request.get('username')

    def get(self):
        error = self.request.get('error')
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10")
        return self.render('front.html', posts=posts, error=error)
        # renders result of above query in front.html stored in variable
        # 'posts'


class PostPage(BlogHandler):

    # gets passed in from below but numbers now assigned randomly
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        # parent only needed because parent was created.
        post = db.get(key)
        print post

        if not post:
            self.error(404)
            return

        return self.render("permalink.html", post=post)


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            return self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect("/login")
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:  # if subject and content there
            p = Post(parent=blog_key(), subject=subject,
                     content=content, created_by=User.by_name(
                self.user.name).name, user_id=self.user.key().id(),
                likes=0, liked_by=[])
            p.put()  # stores element in database
            self.redirect('/blog/%s' % str(p.key().id()))
            # redirects user to above to get id in datastore
            pid = p.key().id()
            print "pid= ", str(pid)
            n1 = User.by_name(self.user.name).name
            print "Post created by", n1

        else:
            error = "subject and content, please!"
            return self.render(
                "newpost.html", subject=subject, content=content, error=error)


class DeletePost(BlogHandler):  # allows users to delete their own blogs

    def get(self, post_id):
        if self.user:  # checks for valid user
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            # checks for valid blog ID
            if post and post.user_id == self.user.key().id():
                self.render('deletepost.html', post=post)
            else:
                if post:
                    self.redirect(
                        '/blog?error='+post_id+' is not a blog id you created')
                else:
                    self.redirect(
                        '/blog?error='+post_id+' is not a current valid\
                         blog id')

        else:
            return self.redirect("/login?error=You need to be logged " +
                                 "in order to delete posts!!")

    def post(self, post_id):  # deletes post upon confirmation
        if not self.user:
            return self.redirect('/blog')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post and post.user_id == self.user.key().id():
            post.delete()
            return self.redirect("/blog/newpost")
        else:
            if post:
                return self.redirect('/blog?error='+post_id+' is not a\
                    blog id you created')
            else:
                msg = ('Please login.  You may only DELETE your own posts.')
                self.render('login-form.html', error=msg)


class EditPost(BlogHandler):

    def get(self, post_id):
        if self.user:  # checks for valid user
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post and post.user_id == self.user.key().id():
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            else:
                if post:
                    return self.redirect('/blog?error='+post_id+' is not a\
                     blog id you created')

                else:
                    return self.redirect('/blog?error='+post_id+' is not a\
                     current valid blog id')
        else:
            return self.redirect("/login?error=You need to be logged " +
                                 "in order to edit posts!!")

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post and post.user_id == self.user.key().id():
            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                post.subject = subject
                post.content = content
                post.put()
                return self.redirect('/blog/%s' % post_id)
            else:
                error = "subject and content, please!"
                return self.render("editpost.html", subject=subject,
                                   content=content, error=error)
        else:
            if post:
                return self.redirect('/blog?error='+post_id+' is not a\
                    blog id you created')
            else:
                msg = ('Please login.  You may only EDIT your own posts.')
                self.render('login-form.html', error=msg)


class LikePost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            return self.redirect("/login?error=You must be logged in to 'like'\
             post.")

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        author = post.created_by
        current_user = self.user.name

        if author == current_user or current_user in post.liked_by:
            return self.redirect("/blog?error=It is bragadocious to\
                 'like' your own post and you may only 'like' a post once.")
        else:
            post.likes = post.likes+1
            post.liked_by.append(current_user)
            post.put()
            return self.redirect("/")


class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name


class NewComment(BlogHandler):

    def get(self, post_id):
        if not self.user:
            return self.redirect("/login")
            return
        post = Post.get_by_id(int(post_id), parent=blog_key())
        subject = post.subject
        content = post.content
        return self.render(
            "newcomment.html", subject=subject, content=content,
            pkey=post.key())

    def post(self, post_id):

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:  # validates post exists
            self.error(404)
            return
        if not self.user:  # make sure user is signed-in
            return self.redirect("/login")
        # create comment
        comment = self.request.get('comment')
        if comment:
            c = Comment(comment=comment, post=post_id, parent=self.user.key())
            c.put()
            return self.redirect('/blog/%s' % str(post_id))
        else:
            error = "Comment Required"
            return self.render("permalink.html", post=post, error=error)


class UpdateComment(BlogHandler):

    def get(self, post_id, comment_id):
        if not self.user:
            return self.redirect("/login")
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            return self.render("updatecomment.html", subject=post.subject,
                               content=post.content, comment=comment.comment)
        else:
            return self.redirect("/blog?error=You may only edit your own\
             comments.")

    def post(self, post_id, comment_id):
        if not self.user:
            return self.redirect("/login")
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment.parent().key().id() == self.user.key().id():
            comment.comment = self.request.get('comment')
            comment.put()
        else:
            return self.redirect("/blog?error=You may only EDIT your own\
             comments.")
        return self.redirect('/blog/%s' % str(post_id))


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        if not self.user:
            return self.redirect("/login")
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            return self.render("deletecomment.html", subject=post.subject,
                               content=post.content, comment=comment.comment)
        else:
            return self.redirect("/blog?error=You may only DELETE your\
             own comments.")

    def post(self, post_id, comment_id):
        if not self.user:
            return self.redirect("/login")
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment.parent().key().id() == self.user.key().id():
            comment.comment = self.request.get('comment')
            comment.delete()
        else:
            return self.redirect("/blog?error=You may only DELETE your own\
             comments.")
        return self.redirect('/blog/%s' % str(post_id))


class Comment(db.Model):
    post = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def render(self):
        self.render("newcomment.html")

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name


class Logout(BlogHandler):

    def get(self):
        self.logout()
        return self.redirect('/blog')


class Unit3Welcome(BlogHandler):

    def get(self):
        if self.user:
            return self.render('welcome.html', username=self.user.name)
        else:
            return self.redirect('/signup')


class Welcome(BlogHandler):

    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            return self.render('welcome.html', username=username)
        else:
            return self.redirect('/unit3/welcome')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               (r'/blog/(\d+)', PostPage),
                               ('/blog/newpost', NewPost),
                               (r'/blog/deletepost/(\d+)', DeletePost),
                               (r'/blog/editpost/(\d+)', EditPost),
                               (r'/blog/likepost/(\d+)', LikePost),
                               (r'/blog/newcomment/([0-9]+)', NewComment),
                               (r'/blog/updatecomment/([0-9]+)/([0-9]+)',
                                UpdateComment),
                               (r'/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/?', BlogFront)
                               ],
                              debug=True)
