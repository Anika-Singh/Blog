import webapp2
import logging
import re
import cgi
import jinja2
import os
import time
import string
import random
import hmac
import hashlib
global value1_in_program
global valid
import urllib2
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext import db
import json



def guess_autoescape(template_name):
   if template_name is None or '.' not in template_name:
	  return False
	  ext = template_name.rsplit('.', 1)[1]
	  return ext in ('html', 'htm', 'xml')

JINJA_ENVIRONMENT = jinja2.Environment(
	loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
	extensions=['jinja2.ext.autoescape'])

def hash_str(s):
	return str(hmac.new("Secret",str(s)).hexdigest())

def make_secure_val(s) :
	return ( str(s) + "|" + hash_str(s))

def check_secure_val(h):
	s = h.split('|')[0]

	if (make_secure_val(s) == h):
		return s
	else:
		return None

userNameRequest= re.compile(r"[A-Za-z0-9_-]{3,20}$")
def Valid_username(username):
	return userNameRequest.match(username)

emailRequest= re.compile(r"^[a-zA-Z0-9_]+@[a-zA-Z0-9_]+\.[A-Z|a-z]+$")
def Valid_email(email):
  return bool(re.search(r"^[a-zA-Z0-9_]+@[a-zA-Z0-9_]+\.[A-Z|a-z]+$", email))

passWordRequest= re.compile(r".{3,20}$")
def Valid_password(password):
	return passWordRequest.match(password)



def make_salt():
	return ''.join(random.choice(string.ascii_letters) for x in range(25))



def make_pw_hash(name, pw, salt=None):
	if (not salt):
		salt = make_salt()
	s = hash_str(str(name) + str(pw) + str(salt))
	return str( s + "|" + salt)

def valid_pw (name, pw, h):
	s = h.split('|')[1]
	if(h == make_pw_hash(name, pw , salt = s)):
		return True
	return False

def get_coord(ip):
	try:
		req = urllib2.Request('http://ip-api.com/json/{0}'.format(ip), headers={'User-Agent' : "Magic Browser"})
		con = urllib2.urlopen( req )
		info = json.loads(con.read())
		return db.GeoPt(str(info['lon']), str(info['lat']) )
	except KeyError:
		   return None



class MyHandler(webapp2.RequestHandler):
	def write(self, *writeArgs):
		self.response.write(" : ".join(writeArgs))

	def render_str(self, template, **params):
		tplt = JINJA_ENVIRONMENT.get_template('templates/'+template)
		return tplt.render(params)
        

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class myPost(db.Model):
	subject = db.StringProperty()
	content = db.TextProperty()
	created = db.DateTimeProperty(auto_now_add=True)
	coords  = db.GeoPtProperty()

class myInfo(db.Model):
	username = db.StringProperty()
	password = db.StringProperty()
	email = db.StringProperty()

class MainPage(MyHandler):

	def get(self):
		logging.info("********** MainPage GET **********")
		value1_in_program = ""
		python_dictionary = {'error' : value1_in_program }
		self.render("newpost.html", **python_dictionary)

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		ipadr = self.request.get("ipadr")

		if (not (content == "" or subject == "")):
			postInst = myPost()
			postInst.subject = subject
			postInst.content = content
			postInst.coords = get_coord(ipadr)
			postInst.put()
			time.sleep(0.2)
			id = postInst.key().id()
			numbers = '/blog/' + str(myPost.get_by_id(id))
			self.redirect('/blog/%s'%str(postInst.key().id()))

		if (content == "" or (subject == "")):
			value1_in_program = "Please enter both title and content"
			python_dictionary = {'error' : value1_in_program }
			self.render("newpost.html", **python_dictionary )
			valid = False

class SignUp(MyHandler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/html'
		python_dictionary = {"username": "" , "Errorusername" : "" , "Errorpassword": "" , "verify" : "" , "Errorverify" : "",  "email" : "", "Erroremail" : ""}
		self.render("signup.html", **python_dictionary)

	def post(self):
		global username
		username = self.request.get("username")
		password = self.request.get("password")
        email = self.request.get("email")
		verify = self.request.get("verify")


		emailString = ""
		passwordString = ""
		usernameString = ""
		verifyString = ""
		newpost = db.GqlQuery("SELECT * FROM myInfo" )
		for i in newpost:
			if(i.username == username):
				usernameString = "Username taken"

		if(not (Valid_email(email)) and not (email == "")):
			emailString = "invalid email"

		if(not verify == password):
			verifyString = "passwords don't match"

		if(not Valid_password(password)):
			passwordString = "invalid password"

		if(not Valid_username(username)):
			usernameString = "invalid username"


		logging.info(emailString)
		logging.info(passwordString)
        logging.info(verifyString)
		logging.info(usernameString)

		python_dictionary = {"username": username, "Errorusername" : usernameString , "Errorpassword": passwordString , "verify" : "" , "Errorverify" : verifyString,  "email" : "", "Erroremail" : emailString }
		self.render("signup.html", **python_dictionary)
		logging.info("HERE 1")
		if (verify == password and Valid_username(username) and Valid_password(password) and  (Valid_email(email) or email == "") and not (usernameString)  ):
			logging.info("HERE 2")
			postInst = myInfo()
			postInst.username = username
			postInst.password = make_pw_hash(username, password)
			postInst.email = email
			postInst.put()

			id = postInst.key().id()
			hashed = make_secure_val(str(id))
			self.response.headers.add_header('Set-Cookie', 'user_id= %s; Path=/ ' %str(hashed))
			time.sleep(0.2)
			self.redirect("/welcome")

class postList(MyHandler):
	def get (self):
		cookieValue = self.request.cookies.get("user_id")
		logging.info("loginCookie=" + cookieValue)
		try:
			info = myInfo.get_by_id(int(check_secure_val(cookieValue)))
			posts = db.GqlQuery("SELECT * FROM myPost ORDER BY created DESC limit 10")
			for post in posts:
				print post.coords.lat, post.coords.lon

			python_dictionary = {'posts' : posts, 'username': info.username }
			self.render("ascii.html", **python_dictionary)

		except TypeError:
			self.render("ascii.html")

class postsPage(MyHandler):
	def get (self, id):

		cookieValue = self.request.cookies.get("user_id")
		logging.info("loginCookie=" + cookieValue)
		try:
			info = myInfo.get_by_id(int(check_secure_val(cookieValue)))
			posts = {myPost.get_by_id(int(id))}


			python_dictionary = {'posts' : posts, 'username': info.username }
			self.render("ascii.html", **python_dictionary)

		except TypeError:
			self.render("ascii.html")

	def post (self, id):
		newpost = {myPost.get_by_id(int(id))}
		self.render("ascii.html", posts = newpost)

class MapPage(MyHandler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/html'
		#page = urllib2.urlopen("http://www.google.com").read()
		python_dictionary = {"username": "" , "Errorusername" : "" , "Errorpassword": "" }
		#self.write(page)
		self.render("map.html")

class LoginPage(MyHandler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/html'
		python_dictionary = {"username": "" , "Errorusername" : "" , "Errorpassword": "" }

		self.render("login.html", **python_dictionary)

	def post(self):
		global username
		username = self.request.get("username")
		password = self.request.get("password")

		usernameString = ""
		passwordString = ""

		newpost = db.GqlQuery("SELECT * FROM myInfo")
		for info in newpost:
			logging.info(info.username)
			if (valid_pw(info.username, password, info.password)):
				logging.info(info.username)
				id = info.key().id()
				hashed = make_secure_val(str(id))

				self.response.headers.add_header('Set-Cookie', 'user_id= %s; Path=/ ' %str(hashed))
				logging.info(username)
				python_dictionary = {"username": username , "Errorusername" : "" , "Errorpassword": "" }

				self.redirect("/blog")

		python_dictionary = {"username": username, "Errorusername" : usernameString , "Errorpassword": passwordString , "error": "Invalid Login"}
		self.render("login.html", **python_dictionary)
class Logout(MyHandler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		self.redirect("/blog")


class successPage(MyHandler):
	def get(self):
		cookieValue = self.request.cookies.get('user_id')


		if (not check_secure_val(cookieValue)):
			self.redirect("/login")
		else:
			newpost = db.GqlQuery("SELECT * FROM myInfo" )
			for info in newpost:

				if( myInfo.get_by_id(int(check_secure_val(cookieValue))).username == info.username):
					a = "Welcome!" + "    " + info.username

					self.response.write(a +  """ <br>
					""" )



application = webapp2.WSGIApplication([
	(r'/signup/?', SignUp ),
	('/', postList),
	(r'/blog/{0,1}', postList),
    (r'/welcome/?', successPage),
	(r'/blog/newpost/?', MainPage),
	('/blog/login', LoginPage),
    (r'/logout/?', Logout),
	('/blog/signup', SignUp),
	('/blog/map', MapPage),
	(r'/login/?', LoginPage),
	(r'/blog/(\d+)', postsPage),

], debug=True)
