'''
# TODO:
  -add unique constraints so there are no duplicate users
  -separate into multiple files
'''

import webapp2

import os
import jinja2
import re
import hmac
import logging
import json
import time
import cgi
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

# for input validation
def valid_username(username):
	return USER_RE.match(username)
	
def valid_password(password):
	return PASSWORD_RE.match(password)

def valid_email(email):
	return EMAIL_RE.match(email)
	
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
 
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):	
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))
	
	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		
# Main Page		
class MainPage(Handler):
    def get(self):
        self.render("index.html")

# Resume Page		
class ResumePage(Handler):
    def get(self):
        self.render("resume.html")
	
# Registration	
class SignupHandler(Handler):
	def render_registration(self, username="", usernameError="", passwordError="", matchError="", email="", emailError=""):
		self.render("registration.html", username=username, usernameError=usernameError, passwordError=passwordError, matchError=matchError, email=email, emailError=emailError)

	def get(self):
		self.render_registration()

	def post(self):
		user_username = str(self.request.get('username'))	# have to use str else self.response.headers.add_header() will complain below
		user_password = self.request.get('password')
		user_verify = self.request.get('verify')
		user_email = self.request.get('email')
	  
		username = valid_username(user_username)
		password = valid_password(user_password)
		email = valid_email(user_email)
		if len(user_email) == 0:	# if user_email length is zero, then email should be True since entering an email is optional
			email = True
		password_match = (user_password == user_verify)	# boolean if both password fields match
		usernameError = ""
		passwordError = ""
		matchError = ""
		emailError = ""
	  
		if not (username and password and password_match and email):
			if not username:
				usernameError = "That isn't a valid username"
			if not password:
				passwordError = "That isn't a valid password"
			if not email and len(user_email) != 0:
				emailError = "That isn't a valid email"
			if user_password != user_verify:
				matchError = "Passwords do not match"	
			#self.render_signon(user_username, usernameError, passwordError, matchError, user_email, emailError)
			self.render_registration(user_username, usernameError, passwordError, matchError, user_email, emailError)
		else:
			username_hash = make_secure_val(user_username)	# used for welcome page when coming from Registration/Signup page
			password_hash = make_secure_val(user_password)	# hash password and insert in DB
			if email and len(user_email) != 0:	# case when user provides an email
				new_user = User(username = user_username, password = password_hash, email = user_email)
			else:
				new_user = User(username = user_username, password = password_hash)
			new_user.put()	# insert User into DB
			self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % username_hash)
			#self.redirect("/welcome?username=" + user_username)
			self.redirect("/welcome")

class WelcomeHandler(webapp2.RequestHandler):
	def get(self):
		username = self.request.cookies.get('username')
		
		h = username.split('|')
		if h[0] == check_secure_val(username):
			self.response.out.write("Welcome, " + h[0])
		else:
			self.redirect("/blog/signup")	

# Blog
class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

MAIN_CACHE = {}
PERMALINK_CACHE = {}
	
class BlogHandler(Handler):
	def render_front(self):
		entries = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")
		if not MAIN_CACHE.get('page'):
			MAIN_CACHE['page'] = time.time()
			
		self.render("front.html", entries=entries, age=int(time.time() - MAIN_CACHE['page']))
		
	def get(self):
		self.render_front()
		
class FormHandler(Handler):
	def render_form(self, subject="", content="", error=""):
		self.render("entry.html", subject=subject, content=content, error=error)
		
	def get(self):
		self.render_form()

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			p = Post(subject = subject, content = cgi.escape(content))
			p.put()
			x = str(p.key().id())
			MAIN_CACHE['page'] = time.time()
			PERMALINK_CACHE['page'] = time.time()
			self.redirect("/blog/%s" % x)
		else:
			error = "we need both a subject and content!" 
			self.render_form(subject, content, error)				

class PostHandler(Handler):
	def render_post(self, post=""):
		self.render("permalink.html", entry = post, age = int(time.time() - PERMALINK_CACHE['page']))
		 
	def get(self, post_id):
		post = Post.get_by_id(int(post_id))
		if not PERMALINK_CACHE.get('page'):
			PERMALINK_CACHE['page'] = time.time()
		if post:
			self.render_post(post)
		else:
			self.error(404)
			return
			
class FlushHandler(Handler):
	def get(self):
		PERMALINK_CACHE.clear()
		MAIN_CACHE.clear()
		self.redirect("/blog")			

# Login
# DB object for Users	
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.TextProperty(required = True)
    email = db.EmailProperty(required = False)
	
# for username validation
SECRET = 'imsosecret'
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

# s: string to be hashed
def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

# h: result of make_secure_val() in the format of: [original string]:[hash value]	
def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

class LoginHandler(Handler):
	def render_signon(self, username="", usernameError="", passwordError=""):
		self.render("login.html", username=username, usernameError=usernameError, passwordError=passwordError)

	def get(self):
		self.render_signon()

	def post(self):
		user_username = str(self.request.get('username'))	# have to use str else self.response.headers.add_header() will complain below
		user_password = self.request.get('password')
	  
		username = valid_username(user_username)
		password = valid_password(user_password)
		passwordMatch = False
		usernameError = ""
		passwordError = ""
	  
		# check if User exists
		user_exists = db.GqlQuery("SELECT * FROM User WHERE username = :1", user_username).get()
		
		# get password if User exists
		if user_exists:
			db_password = user_exists.password
			logging.info('debug: ' + db_password)
			logging.info('debug: ' + check_secure_val(db_password))
			
			# verify that password given matches the hashed password in DB for User
			if user_password != check_secure_val(db_password):
				passwordMatch = False
			else:
				passwordMatch = True
		
		if not (username and password and user_exists and passwordMatch):
			if not username or not user_exists:
				usernameError = "That isn't a valid username"
			
			if not password or not passwordMatch:
				passwordError = "That isn't a valid password"
			self.render_signon(user_username, usernameError, passwordError)
		else:
			username_hash = make_secure_val(user_username)
			self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % username_hash)
			self.redirect("/welcome")

class BlogLogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'username=; Path=/')	# reset cookie
		self.redirect("/blog/signup")
	
class WikiLogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'username=; Path=/')	# reset cookie
		self.redirect("/")
		
# JSON
#PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

class JSONHandler(Handler):
	def get(self, post_id = 0):
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		if post_id != 0:
			post = Post.get_by_id(int(post_id))
		
			if post:
				page = []
				dict = {}
				dict['subject'] = post.subject
				dict['content'] = post.content
				dict['created'] = post.created.strftime("%a %b %d %I:%M:%S %Y")
				dict['last_modified'] = post.last_modified.strftime("%a %b %d %I:%M:%S %Y")
				page.append(dict)
				self.response.out.write(json.dumps(page))
				
		else:
			entries = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")
			list = []
			for entry in entries:
				dict = {}
				dict['subject'] = entry.subject
				dict['content'] = entry.content
				dict['created'] = entry.created.strftime("%a %b %d %I:%M:%S %Y")
				dict['last_modified'] = entry.last_modified.strftime("%a %b %d %I:%M:%S %Y")
				list.append(dict)
			self.response.out.write(json.dumps(list))	
			
# Wiki			
'''
class WikiPost(db.Model):
	page = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	
class WikiHandler(Handler):
	def get(self, page):
		#logging.info('WikiHandler')
		entry = db.GqlQuery("SELECT * FROM WikiPost WHERE page = :1", page).get()
		
		# check if a user is logged in
		logged = self.request.cookies.get('username')
		if logged:
			# if no entry, redirect to edit page, else render the created page
			if not entry:
				self.render('/_edit' + page, loggedIn = True)
			else:	
				self.render("wiki.html", page = page, content = entry.content, loggedIn = True)
		else:
			if not entry:
				self.render('/_edit' + page, loggedIn = False)
			else:	
				self.render("wiki.html", page = page, content = entry.content, loggedIn = False)

	def post(self, page):
		entry = db.GqlQuery("SELECT * FROM WikiPost WHERE page = :1", page).get()
		if not entry:
			p = WikiPost(page = page, content = '')
			p.put()
		self.redirect('/')	
						
class EditWikiHandler(Handler):
	def get(self, page):
		#logging.info('EditWikiHandler')
		entry = db.GqlQuery("SELECT * FROM WikiPost WHERE page = :1", page).get()
		
		# check if a user is logged in
		logged = self.request.cookies.get('username')
		if logged:
			if not entry:
				self.render("edit.html", page = page, loggedIn = True)
			else:
				self.render("edit.html", page = page, content = entry.content, loggedIn = True)
		else:
			if not entry:
				self.render("edit.html", loggedIn = False)
			else:	
				self.render("edit.html", content = entry.content, loggedIn = False)				
	
	def post(self, page):
		content = self.request.get("content")
		entry = db.GqlQuery("SELECT * FROM WikiPost WHERE page = :1", page).get()
		
		if entry:
			entry.content = content
			entry.put()
		else:
			p = WikiPost(page = page, content = content)
			p.put()
		
		self.redirect("%s" % page)
'''
		
app = webapp2.WSGIApplication([('/?', MainPage),
							   ('/main/?', MainPage),
							   ('/resume', ResumePage),
							   ('/welcome', WelcomeHandler),
							   ('/blog/?', BlogHandler), 
							   ('/blog/signup', SignupHandler), 
							   ('/blog/login', LoginHandler),
							   ('/blog/logout', BlogLogoutHandler),
							   ('/blog/newpost', FormHandler), 
							   ('/blog/([0-9]+)', PostHandler),
							   ('/blog/([\d]+).json', JSONHandler),
							   ('/blog[/]?.json', JSONHandler),
							   ('/blog/flush', FlushHandler),
							   #('/logout', WikiLogoutHandler),
							   #('/_edit' + PAGE_RE, EditWikiHandler),
							   #(PAGE_RE, WikiHandler)
							   ], debug=True)