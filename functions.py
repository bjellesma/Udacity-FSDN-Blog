
#templating
import jinja2

#secure
import random
import hashlib
import hmac
from string import letters
import secure

import os
import re

#makes a random string of 5 letters for use in salting passwords
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

##makes a password using sha256
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    #returns salt used as well as the hash
    return '%s,%s' % (salt, h)

#function to check your entered password against the password in the db
def valid_pw(name, password, h):
    #the salt is the first comma seperated parameter stored
    salt = h.split(',')[0]
    #only returns h if it is equal to the hashed password in the database
    return h == make_pw_hash(name, password, salt)


#secure value for making cookies
secret = secure.secret()

#use views as default directory for all views
template_dir = os.path.join(os.path.dirname(__file__), 'views')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)





def make_secure_val(user_id):
    """
    function to make a secure value based on the user id for use in cookies
    """
    return '%s|%s' % (user_id, hmac.new(secret, user_id).hexdigest())


def check_secure_val(secure_val):
    """
    function to test if value is the same secure value made by make_secure_val()
    for use with cookies
    """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#validation functions
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
