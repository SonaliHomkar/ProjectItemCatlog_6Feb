## import database and sqlalchemy for CRUD operations ##
import re
import hmac
import random
import hashlib
from string import ascii_letters,ascii_uppercase, digits
from database_setup import Base,Category,Item,User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response
import httplib2
import json
import requests

from flask import Flask,render_template, request, redirect, url_for,flash, jsonify
app = Flask(__name__)


## create session and connect to database ##
engine = create_engine('sqlite:///ItemCatlog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()



SECRET = 'imsosecret'
USERNAME = ""

# these functions are used for password hashing and salt techniques
def make_salt(length = 5):
    return ''.join(random.choice(ascii_letters) for x in range(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256((name + pw + salt).encode('utf-8')).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# This function is used to check if the user already exist
def checkUser(strName):
        objUser = session.query(User).filter_by(userName=strName).one_or_none()
        return objUser

# This function is used to validate if the user has entered required fields
def validateUser(strName,strPassword):
    if strName == "" or strPassword =="":
        return True

# This function creates cookie once user logs in 
def set_secure_cookie(name, val):
    cookie_val = make_pw_hash(name, val)
    app.response_class.set_cookie(self,UserId, cookie_val,path="/")
    
# This function checkes if the cookie for User Id 
def checkCookie():
    if request.cookies.get("UserId"):
        return True

# This function is used to validate category
def validateCategory(strCategory):
    if strCategory != "":
        return True
    

# This function is used to validate items
def validateItem(itemName):
    if itemName != "":
        return True


# This function displays the login page 
@app.route('/login', methods=['GET','POST'])
def loginUser():
        if request.method == 'POST':
                error= ""
                params = dict(error=error)
                invalidUser = validateUser(request.form['txtName'],request.form['txtpassword'])

                if invalidUser:
                    params['error'] = "Please enter User name or password"
                    return render_template('loginUser.html',**params) 

                objUser = checkUser(request.form['txtName'])
                
                if objUser: 
                        hashstr = valid_pw(request.form['txtName'],request.form['txtpassword'],objUser.userPassword)
                        if hashstr:
                                redirect_to_index = redirect(url_for('showCategory'))
                                response = app.make_response(redirect_to_index)
                                cookie_val = request.form['txtName']
                                response.set_cookie("UserId",cookie_val)
                                login_session['provider'] = "app"
                                login_session['username'] = request.form['txtName']
                                return response 
                        else:
                                params['error'] = "Incorrect password please enter again"
                                return render_template('loginUser.html',**params)
                else:
                        params['error'] = "User id does not exist..please sign up for new user"
                        return self.render_template('loginUser.html',**params)
        else:
            state = ''.join(random.choice(ascii_uppercase + digits)
                        for x in range(32))
            login_session['state'] = state
            return render_template('loginUser.html',STATE=state)

# This function displays the login page 
@app.route('/showUsers', methods=['GET','POST'])
def showUser():
        objUsers = session.query(User).all()
        return render_template('showUsers.html',objUsers=objUsers)

# This function retrieves items for selected category 
@app.route('/getCategory/<int:cat_id>', methods=['GET','POST'])
def getCategory(cat_id):
    items = session.query(Item).filter_by(category_id = cat_id).all()
    return jsonify(items=[i.serialize for i in items])    
        
# This function displays the User sign up page 
@app.route('/userSignUp', methods=['GET','POST'])
def usersSignUp():
    if request.method == 'POST':
        strname = request.form['txtName']
        strpassword = request.form['txtpassword']
        strvarpassword = request.form['txtrepassword']
        stremail = request.form['txtemail']

        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PWD_RE = re.compile(r"^.{3,20}$")
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        have_error = False
        params = dict(strname=strname, strpassword=strpassword, strvarpassword=strvarpassword, stremail=stremail)

        if not ( strname and USER_RE.match(strname)):
            params['msg'] = "That's not a valid user name.."
            have_error = True
        if not (strname and PWD_RE.match(strpassword)):
            params['pwdmsg'] = "That's not a valid password"
            have_error = True
        if strpassword != strvarpassword:
            params['varmsg'] = "verify password do not match"
            have_error = True
        if stremail != "" and not EMAIL_RE.match(stremail):
            params['emailmsg'] = "That's not a valid email"
            have_error = True
             
        if have_error:
            return render_template("UserSignUp.html",**params )
        else:
                if(checkUser(strname)):
                        params['error'] = "User already exist"
                        return render_template("UserSignUp.html",**params )
                else:
                        newUser = User(userName=strname,userPassword=make_pw_hash(strname,strpassword),userEmail=stremail)
                        session.add(newUser)
                        session.commit()
                        flash("New user created!!!")
                        return redirect(url_for('loginUser'))
    else:
        return render_template('UserSignUp.html')

# This function displays the home page with categories and newly added 5 categories. 
@app.route('/logout')
def logout():
    redirect_to_index = redirect(url_for('loginUser'))
    response = app.make_response(redirect_to_index)
    if login_session['provider'] == "google":
        gdisconnect()
    if login_session['provider'] == 'facebook':
        fbdisconnect()
    else:
        del login_session['provider'] 
        del login_session['username'] 
        response.set_cookie("UserId",expires=0)
    flash("you have been successfully logged out!!")
    return response
     
    

# This function displays the home page with categories and newly added 5 categories. 
@app.route('/')
def showCategory():
        if checkCookie():
            category = session.query(Category).all()
            items = session.query(Item).order_by(Item.id.desc()).limit(5).all()
            return render_template('category.html',category=category,items=items)
        else:
            return redirect(url_for('loginUser'))

# This function gets the Items of provided category in JSON format
@app.route('/ItemCatlog/<int:cat_id>/')
def getItems(cat_id):
        if checkCookie():
            items = session.query(Item).filter_by(category_id = cat_id).all()
            return jsonify(items=[i.serialize for i in items])
        else:
            return redirect(url_for('loginUser'))

# This function adds a new category to the database
@app.route('/ItemCatlog/newCategory/', methods=['GET','POST'])
def newCategory():
        if checkCookie():
            if request.method == 'POST':
                if validateCategory(request.form['category']):
                    #return "Username :" +  request.cookies.get("UserId")
                    newItem = Category(catName = request.form['category'],userName=request.cookies.get("UserId"))
                    session.add(newItem)
                    session.commit()
                    flash("New Category created!!!")
                    return redirect(url_for('showCategory'))
                else:
                    error = "Please enter Category"
                    return render_template('newCategory.html',error=error)
            else:
                return render_template('newCategory.html')
        else:
            return redirect(url_for('loginUser'))

# This function updates selected category
@app.route('/ItemCatlog/<int:cat_id>/edit/', methods=['GET','POST'])
def editCategory(cat_id):
        if checkCookie():
            editedItem = session.query(Category).filter_by(id=cat_id).one()
            if request.method == 'POST':
                if validateCategory(request.form['category']):
                    editedItem.catName = request.form['category']
                    editedItem.userName=request.cookies.get("UserId")
                    session.add(editedItem)
                    session.commit()
                    flash("Category edited!!!")
                    return redirect(url_for('showCategory'))
                else:
                    error = "Please enter Category!!"
                    return render_template('editCategory.html',error=error,cat_id=cat_id,i=editedItem)
            else:
                return render_template('editCategory.html',cat_id=cat_id,i=editedItem)
        else:
            return redirect(url_for('loginUser'))

# This function deletes category
@app.route('/ItemCatlog/<int:cat_id>/delete/', methods = ['GET','POST'])
def deleteCategory(cat_id):
        if checkCookie():
            deletedItem = session.query(Category).filter_by(id=cat_id).one()
            if request.method == 'POST':
                session.delete(deletedItem)
                session.commit()
                flash("Category Deleted!!!")
                return redirect(url_for('showCategory'))
            else:
                return render_template('deleteCategory.html',cat_id=cat_id,i=deletedItem)
        else:
            return redirect(url_for('loginUser'))


# This function adds new Item to the category
@app.route('/ItemCatlog/addItem/', methods = ['GET','POST'])
def addItem():
    if checkCookie():
        if request.method == 'POST':
            if validateItem(request.form['itemName']):
                newItem = Item(itemName = request.form['itemName'],description = request.form['description'],
                               userName = login_session['username'],category_id=request.form['ddlCategory'])
                session.add(newItem)
                session.commit()
                flash("New Item created!!")
                return redirect(url_for('showCategory'))
            else:
                error = "Please enter Item name!!"
                category = session.query(Category).all()
                return render_template('addNewItem.html',error=error,categories=category)
        else:
                category = session.query(Category).all()
                return render_template('addNewItem.html',categories=category)
    else:
        return redirect(url_for('loginUser'))  

# Task 1 : Create route for adding new item function here
@app.route('/ItemCatlog/<int:cat_id>/displayItem/', methods = ['GET','POST'])
def displayItem(cat_id):
    if checkCookie():
        Author = False 
        category = session.query(Category).all()
        items = session.query(Item).filter_by(category_id=cat_id).all()
        return render_template('category.html',category=category,items=items,Author=Author)
    else:
        return redirect(url_for('loginUser'))  

# Task 1 : Create route for adding new item function here
@app.route('/ItemCatlog/<int:item_id>/displayItemDetail/', methods = ['GET','POST'])
def displayItemDetails(item_id):
    if checkCookie():
        Author = False 
        items = session.query(Item.id,Item.description,Item.itemName,
                              Category.catName,Item.userName).join(Category,Category.id==Item.category_id).filter(Item.id==item_id).all()
        #return ("username : " + items[0].userName)
        if(login_session['username'] == items[0].userName):
            Author = True
        return render_template('itemDetails.html',items=items,Author=Author)
    else:
        return redirect(url_for('loginUser'))  


# This function is intended for editing items
@app.route('/ItemCatlog/<int:item_id>/EditItem/', methods = ['GET','POST'])
def editItemDetails(item_id):
    if checkCookie():
        if request.method == 'POST':
            if validateItem(request.form['itemName']):
                editedItem = session.query(Item).filter_by(id=item_id).one()
                editedItem.itemName =  request.form['itemName']
                editedItem.description = request.form['description']
                editedItem.category_id = request.form['ddlCategory']
                session.add(editedItem)
                session.commit()
                flash("Item edited!!")
                return redirect(url_for('showCategory'))
            else:
                error = "Please enter Item !!"
                category = session.query(Category).all()
                return render_template('addNewItem.html',error=error,categories=category)
        else:
            category = session.query(Category).all()
            items = session.query(Item.id,Item.description,Item.itemName,Category.catName,
                                  Item.category_id,Item.userName).join(Category,
                                                                       Category.id==Item.category_id).filter(Item.id==item_id).all()
            return render_template('editItemDetails.html',items=items,category=category)
    else:
        return redirect(url_for('loginUser'))  



# This function deletes the given item id
@app.route('/ItemCatlog/<int:item_id>/DeleteItem/', methods = ['GET','POST'])
def DeleteItem(item_id):
    if checkCookie():
        deletedItem = session.query(Item).filter_by(id=item_id).one()
        if request.method == 'POST':
                session.delete(deletedItem)
                session.commit()
                flash("Item Deleted!!")
                return redirect(url_for('showCategory'))
        else:
                return render_template('DeleteItem.html')
    else:
        return redirect(url_for('loginUser'))



# Making an API endpoint(get request) to get all categories 
@app.route('/ItemCatlog/JSON')
def categoryJason():
    if checkCookie():
        
        catlist = []
        
        jsonstr = ""
        category = session.query(Category).all()
        #catlist.append(cDict)
        for j in category:
            #catlist.append(j.serialize)
            items = session.query(Item).filter_by(category_id=j.id).all()
            itemlist = []
            #idict = { "items":[] }
            for i in items:
                itemlist.append(i.serialize)
            idict = {"id" : j.id, "Name" : j.catName, "items": itemlist }
            catlist.append(idict)
            
        #cDict =  {"categories": catlist}
        
        return jsonify({"categories": catlist})
        
        
    else:
        return redirect(url_for('loginUser'))


# Making an API endpoint(get request) to get all categories 
@app.route('/ItemCatlog/JSONNew')
def categoryJasonNew():
    if checkCookie():
        catlist = []
        
        jsonstr = ""
        category = session.query(Category).all()
        for j in category:
            catlist.append(j.serialize)
            items = session.query(Item).filter_by(category_id=j.id).all()
            itemlist = []
            for i in items:
                itemlist.append(i.serialize)
            if items:
                catlist.append(itemlist)
                
        
        jsonstr =  json.dumps(catlist,indent=4)
        return jsonstr
        
    else:
        return redirect(url_for('loginUser'))


# a method to call the facebook server to run the api
@app.route('/fbconnect',methods=['POST'])
def fbconnect():
        access_token = request.data

        app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']

        app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']

        url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]

         # Use token to get user info from API
        userinfo_url = "https://graph.facebook.com/v2.8/me"
        '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
        '''
        token = result.split(',')[0].split(':')[1].replace('"', '')

        url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        # print "url sent for API access:%s"% url
        output = "API JSON result: %s" % result
        
        
        data = json.loads(result)
        login_session['provider'] = 'facebook'
        login_session['username'] = data["name"]
        login_session['email'] = data["email"]
        login_session['facebook_id'] = data["id"]
        
        # The token must be stored in the login_session in order to properly logout
        login_session['access_token'] = token

        # Get user picture
        url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        data = json.loads(result)

        login_session['picture'] = data["data"]["url"]

        # see if user exists
        '''
        user_id = getUserID(login_session['email'])
        if not user_id:
        '''
        user_id = createUser(login_session)
        login_session['user_id'] = user_id
        
        
        output = ''
        output += '<h1>Welcome, '
        output += login_session['username']

        output += '!</h1>'
        output += '<img src="'
        output += login_session['picture']
        output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

        flash("Now logged in as %s" % login_session['username'])
        return output

# Method to call FB server to disconnect and delete the token
@app.route('/fbdisconnect')
def fbdisconnect():
        facebook_id = login_session['facebook_id']
        access_token = login_session['access_token']
        url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
        h = httplib2.Http()
        result = h.request(url, 'DELETE')[1]
        del login_session['provider'] 
        del login_session['username'] 
        del login_session['facebook_id'] 
        del login_session['access_token'] 
        del login_session['picture']
        del login_session['user_id'] 
        return "you have been logged out"
    


# a method to call the google server to run the api
@app.route('/gconnect',methods=['POST'])
def gconnect():
    if request.method == 'POST':
            
        # Validate state token
        if request.args.get('state') != login_session['state']:
                response = make_response(json.dumps('Invalid state parameter'),401)
                response.headers['Content-Type'] = 'application/json'
                return response
        # Obtain authorization code
        code = request.data
        
        try:
            oauth_flow = flow_from_clientsecrets('client_secrets.json',scope = 'https://www.googleapis.com/auth/gmail.readonly')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade' +
                                                'the authorization code'),401)
            response.headers['Content-Type'] = 'application/json'
            return response
    
        # check that access token is valid
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url,'GET')[1])
        
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
                response = make_response(json.dumps(result.get('error')),501)
                response.headers['Content-Type'] = 'application/json'
                return response
        # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result['user_id'] != gplus_id:
                response = make_response(json.dumps("Token's user id" +
                                                    "doesn't match given" +
                                                    "user id"), 401)
                response.headers['Content-Type'] = 'application/json'
                return response


        # Verify that the access token is valid for this app.
        if result['issued_to'] != CLIENT_ID:
                response = make_response(json.dumps("Token's clinet id" +
                                                    "doesn't match " +
                                                    "app's id"),401)
                print ("Token's id doesn't match app's id")
                response.headers['Content-Type'] = 'application/json'
                return response

        # check to see if the user is already logged in
        stored_access_token = login_session.get('access_token')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_access_token is not None and gplus_id == stored_gplus_id:
            response = make_response(json.dumps('Current user is already connected.'),
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

        data = answer.json()
        login_session['provider'] = 'google'
        login_session['username'] = data['name']
        login_session['picture'] = data['picture']
        login_session['email'] = data['email']

        user_id = getUserId(login_session['email'])
        if  not user_id:
                user_id = createUser(login_session)
                strUser = "New User"
        else:
                strUser = ("User Already exist")

        login_session['user_id'] = user_id


        output = ''
        output += '<h1>Welcome, '
        output += login_session['username']
        output += '!</h1>'
        output += '<img src="'
        output += login_session['picture']
        output += 'status : ' + strUser
        output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
        flash("you are now logged in as %s" % login_session['username'])
        print ("done!")
        return output

@app.route("/gdisconnect")
def gdisconnect():
        access_token = login_session.get('access_token')
        if access_token is None:
                response = make_response(json.dumps("Current user is already" +
                                                            "not connected"),401)
                response.headers['Content-Type'] = 'application/json'
                return response
        
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        
        if result['status'] == '200':
                del login_session['access_token']
                del login_session['gplus_id']
                del login_session['username']
                del login_session['picture'] 
                del login_session['email']

                response = make_response(json.dumps('Successfully disconnected'),
                                         200)
                response.headers['Content-Type'] = 'application/json'
                return response
        else:
                response = make_response(json.dumps('Failed to revoke token for '+
                                                    'a given user'), 400)
                response.headers['Content-Type'] = 'application/json'
                return response

def createUser(login_session):
        newUser = User(userName=login_session['username'],
                       userEmail=login_session['email'])
                       
        session.add(newUser)
        session.commit()
        user = session.query(User).filter_by(id=newUser.id).one()
        return user.id

def getUserId(email):
        try:
                user = session.query(User).filter_by(userEmail=login_session['email']).one()
                return user.userEmail
        except:
                return None





if __name__ == "__main__":
        app.secret_key = 'super_secret_key'
        app.debug = True
        app.run(host = '0.0.0.0', port = 5500)
