# import flask classes from flask library
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   jsonify)
# CRUD functionality
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
# Password hashing
from flask.ext.bcrypt import Bcrypt
import random
import string
import hmac
# Login info
from flask import session as login_session
# Creates flow object that stores oauth2 parameters
from oauth2client.client import flow_from_clientsecrets
# If run into error exchanging token for authorization, can use this
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
# Regex expressions
import re
import os

# Create instance of flask class with name of running application as argument
# Whenever run an app in python, variable called __name__ gets defined.
app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

# For password hashing
bcrypt = Bcrypt(app)
# Create instance of engine
engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Used to stop static file caching
@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r


# Function to check if user is logged in
def isLoggedIn():
    print login_session.get('username')
    return login_session.get('username')


# Function to determine if the current user and
# user of a category or item to be CRUD'd match
def isCorrectUser(user1, user2):
    return user1 == user2


# Displays Catalog Home Page
@app.route('/')
@app.route('/catalog')
def catalog():
    # Obtains all categories and items in database
    categories = session.query(Category).all()
    items = session.query(Item).all()
    # Renders home page
    return render_template('catalog.html', categories=categories, items=items,
                           login_session=login_session)


# CATEGORY PAGES #
# Category Page
@app.route('/category/<int:category_id>')
def category(category_id):
    # Find the category based on the id
    category = session.query(Category).filter_by(id=category_id).one()
    # Find all items for the category
    items = session.query(Item).filter_by(category_id=category_id).limit(10)
    # Renders category
    return render_template('category.html', category=category, items=items,
                           login_session=login_session)


# New Category Page
@app.route('/category/new', methods=['GET', 'POST'])
def newCategory():
    # POST requests
    if request.method == 'POST':
        # Is the user logged in?
        if isLoggedIn():
            # Get the user id
            user_id = login_session['user_id']
            # Gets new category name from form
            name = request.form['category-name']
            # Checks to see if duplicate category
            if session.query(Category).filter_by(name=name).all():
                # Flash duplicate category
                flash("Duplicate Category ;(")
                return redirect(url_for('newCategory'))
            else:
                # Outputs content to database
                newCategory = Category(user_id=user_id, name=name)
                session.add(newCategory)
                session.commit()
                # Redirect to main catalog page
                return redirect(url_for('catalog'))
        else:
            # Renders login page
            return redirect(url_for('login'))
    # GET requests
    else:
        # Check if user logged in or not
        if isLoggedIn():
            # Renders new category page
            return render_template('newCategory.html',
                                   login_session=login_session)
        else:
            # Renders login page
            return redirect(url_for('login'))


# Edit Category Page
@app.route('/category/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    # POST requests
    if request.method == 'POST':
        # The current user_id and the category's user_id
        this_user_id = login_session['user_id']
        post_user_id = \
            session.query(Category).filter_by(id=category_id).one().user_id
        # Is the user logged in and the correct user?
        if isLoggedIn() and isCorrectUser(this_user_id, post_user_id):
            # Gets new category name from form
            name = request.form['edit-category-name']
            # Checks to see if duplicate category
            if session.query(Category).filter_by(name=name).all():
                # Flash duplicate category
                flash("Duplicate Category ;(")
                return redirect(url_for('editCategory',
                                        category_id=category_id))
            else:
                # Find Category database entry with name=category,
                # update with form entry
                editCategory = \
                    session.query(Category).filter_by(id=category_id).one()
                editCategory.name = name
                session.add(editCategory)
                session.commit()
                # Redirect to main catalog page
                return redirect(url_for('catalog'))
        else:
            # Renders login page
            return redirect(url_for('login'))
    else:
        # The current user_id and the category's user_id
        this_user_id = login_session['user_id']
        post_user_id = \
            session.query(Category).filter_by(id=category_id).one().user_id
        # Is the user logged in and the correct user?
        if isLoggedIn() and isCorrectUser(this_user_id, post_user_id):
            # Finds category, based on category_id
            category = session.query(Category).filter_by(id=category_id).one()
            # Renders edit category page
            return render_template('editCategory.html', category=category,
                                   login_session=login_session)
        else:
            # Renders login page
            return redirect(url_for('login'))


# Delete Category Page
@app.route('/category/<int:category_id>/delete', methods=['GET', 'POST'])
def deleteCategory(category_id):
    # POST requests
    if request.method == 'POST':
        # The current user_id and the category's user_id
        this_user_id = login_session['user_id']
        post_user_id = \
            session.query(Category).filter_by(id=category_id).one().user_id
        # Is the user logged in and the correct user?
        if isLoggedIn() and isCorrectUser(this_user_id, post_user_id):
            # Find Category database entry with name=category,
            # update with form entry
            deleteCategory = \
                session.query(Category).filter_by(id=category_id).one()
            session.delete(deleteCategory)
            session.commit()
            # Redirect to main catalog page
            return redirect(url_for('catalog'))
        else:
            # Renders login page
            return redirect(url_for('login'))
    else:
        # The current user_id and the category's user_id
        this_user_id = login_session['user_id']
        post_user_id = \
            session.query(Category).filter_by(id=category_id).one().user_id
        # Is the user logged in and the correct user?
        if isLoggedIn() and isCorrectUser(this_user_id, post_user_id):
            # Finds category, based on category_id
            category = session.query(Category).filter_by(id=category_id).one()
            # Renders edit category page
            return render_template('deleteCategory.html', category=category,
                                   login_session=login_session)
        else:
            # Renders login page
            return redirect(url_for('login'))


# ITEM PAGES #
# Item Page
@app.route('/category/<int:category_id>/item/<int:item_id>',
           methods=['GET', 'POST'])
def item(category_id, item_id):
    # Find the category/item
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    # Renders item page
    return render_template('item.html', category=category, item=item,
                           login_session=login_session)


# New Item Page
@app.route('/category/item/new', methods=['GET', 'POST'])
def newItem():
    # POST requests
    if request.method == 'POST':
        # Is the user logged in?
        if isLoggedIn():
            # Get the logged in user id
            user_id = login_session['user_id']
            # Gets new item name, description, category from form
            name = request.form['new-item-name']
            description = request.form['new-item-description']
            category = request.form['new-item-category']
            category_id = \
                session.query(Category).filter_by(name=category).one().id
            # Checks to see if duplicate category
            if session.query(Item).filter_by(
                    category_id=category_id).filter_by(name=name).first():
                # Flash duplicate category
                flash("Duplicate Item ;(")
                return redirect(url_for('newItem'))
            else:
                # Outputs content to database
                newItem = Item(user_id=user_id, category_id=category_id,
                               name=name, description=description)
                session.add(newItem)
                session.commit()
                # Redirect to main catalog page
                return redirect(url_for('catalog'))
        else:
            # Renders login page
            return redirect(url_for('login'))
    # GET requests
    else:
        # Is the user logged in?
        if isLoggedIn():
            # Obtains all categories in database
            categories = session.query(Category).all()
            # Renders new category page
            return render_template('newItem.html', categories=categories,
                                   login_session=login_session)
        else:
            # Renders login page
            return redirect(url_for('login'))


# Edit Item Page
@app.route('/category/<int:category_id>/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editItem(category_id, item_id):
    # POST requests
    if request.method == 'POST':
        # The current user_id and the item's user_id
        this_user_id = login_session['user_id']
        post_user_id = session.query(Item).filter_by(id=item_id).one().user_id
        # Is the user logged in and the correct user?
        if isLoggedIn() and isCorrectUser(this_user_id, post_user_id):
            # Gets new category name from form
            name = request.form['edit-item-name']
            description = request.form['edit-item-description']
            category = request.form['edit-item-category']
            # Find Item database entry with id=item_id, update with form entry
            editItem = session.query(Item).filter_by(id=item_id).one()
            editItem.name = name
            editItem.description = description
            editItem.category_id = \
                session.query(Category).filter_by(name=category).one().id
            session.add(editItem)
            session.commit()
            # Redirect to main catalog page
            return redirect(url_for('catalog'))
        else:
            # Renders login page
            return redirect(url_for('login'))
    else:
        # The current user_id and the item's user_id
        this_user_id = login_session['user_id']
        post_user_id = session.query(Item).filter_by(id=item_id).one().user_id
        # Is the user logged in and the correct user?
        if isLoggedIn() and isCorrectUser(this_user_id, post_user_id):
            # Obtains all categories in database
            categories = session.query(Category).all()
            # Finds category, based on category_id
            category = session.query(Category).filter_by(id=category_id).one()
            # Finds items, based on item_id
            item = session.query(Item).filter_by(id=item_id).one()
            # Renders edit item page
            return render_template('editItem.html', categories=categories,
                                   category=category, item=item,
                                   login_session=login_session)
        else:
            # Renders login page
            return redirect(url_for('login'))


# Delete Item Page
@app.route('/category/<int:category_id>/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    # POST requests
    if request.method == 'POST':
        # The current user_id and the item's user_id
        this_user_id = login_session['user_id']
        post_user_id = session.query(Item).filter_by(id=item_id).one().user_id
        # Is the user logged in and the correct user?
        if isLoggedIn() and isCorrectUser(this_user_id, post_user_id):
            # Find Item database entry with name=category,
            # update with form entry
            deleteItem = session.query(Item).filter_by(id=item_id).one()
            session.delete(deleteItem)
            session.commit()
            # Redirect to main catalog page
            return redirect(url_for('catalog'))
        else:
            # Renders login page
            return redirect(url_for('login'))
    else:
        # The current user_id and the item's user_id
        this_user_id = login_session['user_id']
        post_user_id = session.query(Item).filter_by(id=item_id).one().user_id
        # Is the user logged in and the correct user?
        if isLoggedIn() and isCorrectUser(this_user_id, post_user_id):
            # Finds category, based on category_id
            category = session.query(Category).filter_by(id=category_id).one()
            # Finds item, based on category_id
            item = session.query(Item).filter_by(id=item_id).one()
            # Renders edit category page
            return render_template('deleteItem.html',
                                   category=category, item=item,
                                   login_session=login_session)
        else:
            # Renders login page
            return redirect(url_for('login'))


# API ENDPOINTS #
# For category requests with url variables
@app.route('/api')
def category_items():
    # Returns items specific to category
    category = request.args.get('category')
    category_id = session.query(Category).filter_by(name=category).one().id
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(items=[i.serialize for i in items])


# All categories
@app.route('/api/categories', methods=['GET', 'POST'])
def all_categories():
    # Return all items in database
    categories = session.query(Category).all()
    return jsonify(categories=[category.serialize for category in categories])


# All Items
@app.route('/api/items', methods=['GET', 'POST'])
def all_items():
    # Return all items in database
    items = session.query(Item).all()
    return jsonify(items=[i.serialize for i in items])


# All Items
@app.route('/api/items/<int:item_id>', methods=['GET', 'POST'])
def each_item(item_id):
    # Return all items in database
    item = session.query(Item).filter_by(id=item_id).all()
    return jsonify(item=[i.serialize for i in item])


# AUTHORIZATION #
# Validate
def validate_email(email):
    regex = "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    if not session.query(User).filter_by(email=email).first() and \
            (re.match(regex, email) is not None):
        return True


def validate_username(username):
    regex = "(^([a-zA-Z0-9!@#$%^&*]{5,30}))"
    if not session.query(User).filter_by(username=username).first() and \
            re.match(regex, username) is not None:
        return True


def validate_passwords(password1, password2):
    regex = \
        "(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[^a-zA-Z])(?=.*?[^a-zA-Z0-9]).{9,35}"
    if password1 == password2 and re.match(regex, password1) is not None:
        return True


# Function that executes user signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # POST requests
    if request.method == 'POST':
        # Extract email, username, password from form using request.form
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirmPassword = request.form['confirm-password']
        # Hash password
        pw_hash = bcrypt.generate_password_hash(password)

        # If all data valid, send to database
        if validate_email(email) and validate_username(username) and \
                validate_passwords(password, confirmPassword):

            # Create new user object
            newUser = User(email=email, username=username, password=pw_hash)
            # Add to session
            session.add(newUser)
            # Commit to db
            session.commit()

            # Find the username, id of the logged in user
            login_session['username'] = username
            login_session['user_id'] = \
                session.query(User).filter_by(username=username).one().id

            # Redirect to blogfront page
            return redirect(url_for('catalog'))
        # If data not valid, stay on page
        else:
            # Flash incorrect login
            flash("Invalid Signup Information ;(")
            return render_template('login-signup.html', email=email,
                                   username=username)


# Function that executes user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Create anti-forgery state token that will
    be used later for this session'''
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # POST requests
    if request.method == 'POST':
        # Get username and login from form
        username = request.form['login-username']
        password = request.form['login-password']
        # Hash password
        pw_hash = bcrypt.generate_password_hash(password)

        # Check the username and password. If they match a user,
        # login and redirect to blogfront
        sessionQuery = session.query(User).filter_by(username=username)
        if sessionQuery.all() and \
                bcrypt.check_password_hash(pw_hash, password):
            # Store username and id in login_session
            login_session['username'] = username
            login_session['user_id'] = sessionQuery.one().id

            # Redirect to blogfront
            return redirect(url_for('catalog'))

        # If the username and password don't match, redirect to the login page.
        else:
            # Flash incorrect login
            flash("Incorrect Login ;(")

            # Redirect to login form
            return render_template('login-signup.html', STATE=state)
    else:
        # Redirect to login form
        return render_template('login-signup.html', STATE=state)


# Function that logs user out
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    # Check which provider the user is using
    provider = login_session.get('provider')

    # Disconnect accordingly
    if provider == 'google':
        return redirect(url_for('gdisconnect'))
    elif provider == 'facebook':
        return redirect(url_for('fbdisconnect'))
    else:
        # Delete username and user_id from login session
        login_session.pop('username', None)
        login_session.pop('user_id', None)

        # Redirect to the homepage
        return redirect(url_for('catalog'))


# GOOGLE LOGIN
# Helper functions for GConnect
def createUser(login_session):
    newUser = User(username=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Route and function that accepts post requests
@app.route('/gconnect', methods=['POST'])
# 1. Confirm login session same on client and server, so no malicous attacks
# 2. Receive one-time token
# 3. Convert one-time token to a credentials object
# 4. Check to see credentials object holds valid access token
# 5. Check that valid access token is correct access token
def gconnect():
    # STEP 1
    # Confirm token client sent to server same as token server sent to client
    # Helps ensure user making request, and not a malicious script
    # Examines state token passed in and compares to state of login session
    if request.args.get('state') != login_session['state']:
        # If don't match, create a response of an invalid state token and
        # return message to the client
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # STEP 2
    # If tokens correct, can proceed and request one-time code from server.
    code = request.data
    print "CODE IS %s" % code
    # STEP 3
    # Try to use one-time code to exchange for credentials object
    try:
        # Exchange the one-time code into a credentials object
        # Creates oauth flow object, adds client secret key info to it
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        # Specify this is the one-time code the server will be sending off
        oauth_flow.redirect_uri = 'postmessage'
        # Initiate exchange with step2_exchange function
        # Exchanges auth code for credentials object
        credentials = oauth_flow.step2_exchange(code)
    # If error, throw this flow exchange error,
    # and send the response as a JSON object
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # STEP 4
    # Check that the access token is valid.
    # Store access token in variable
    access_token = credentials.access_token
    # Append access token to url, Google API Server can confirm its validity
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Create a json get request containing url and access token,
    # Store result in result variable
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    # Compare id of token in credentials object with id returned by
    # Google API Server
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        print "Verify the access token is used for the intended user"
        return response

    # Verify that the access token is valid for this app.
    # If client Id's do not match, shouldn't allow.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check if user already logged in.
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    # Store user info in object called data
    data = answer.json()
    # Store info we want into login_session
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # If the above works, we should get a message
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += """' " style = "width: 300px; height: 300px;border-radius: 150px;
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '"""
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# Route and function that accepts post requests
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    # Grab credentials field again
    access_token = login_session['access_token']
    # If credentials field is empty, do not have record of a user,
    # so no one to disconnect from app
    if access_token is None:
        # Return a 401 error for this case.
        response = \
            make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % \
        login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('catalog'))
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# FACEBOOK LOGIN
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # Protect against cross-site forgery attacks
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Exchange short-lived token for a long-lived token
    access_token = request.data
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = """https://graph.facebook.com/oauth/access_token?
    grant_type=fb_exchange_token&client_id=%s&client_secret=%s&
    fb_exchange_token=%s""" % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange
        we have to split the token first on commas and select the first index
        which gives us the key : value for the server access token then we
        split it on colons to pull out the actual token value and replace the
        remaining quotes with nothing so that it can be used directly in the
        graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = """https://graph.facebook.com/v2.8/me?access_token=%s&
    fields=name,id,email""" % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Populate login session
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # # Get user picture
    url = """https://graph.facebook.com/v2.8/me/picture?access_token=%s
    &redirect=0&height=200&width=200""" % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ''' " style = "width: 300px; height: 300px;border-radius: 150px;
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '''

    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % \
        (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]

    # Delete login_session values
    del login_session['provider']
    del login_session['username']
    del login_session['email']
    del login_session['facebook_id']
    del login_session['picture']
    del login_session['access_token']

    return redirect(url_for('catalog'))


# application run by python interpreter gets name __main__
# all other imported python files get name set to name of python file
# if __name__ makes sure server only runs if script run from py interpreter,
# and not as imported code.
if __name__ == '__main__':
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    # flash will use to create sessions for users.
    app.secret_key = 'super_secret_key'
    # Server reloads itself each time a load change,
    # and gives helpful debugger.
    app.debug = True
    # Run function used to run local server with application.
    # By default, server only accessible on host machine
    # But because using Vagrant, must change port to 0.0.0.0 to state that
    # web server should listen on all public IP Addresses
    # and make server publicly available
    app.run(host='0.0.0.0', port=5000)
    # app.run(port = 5000)
