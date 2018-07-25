from flask import Flask, render_template, request, flash, session, redirect
import re
from mysqlconnection import MySQLConnector
import md5
import os, binascii # include this at the top of your file


app = Flask(__name__)

app.secret_key = "secretsecret"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
mysql = MySQLConnector(app, "wall_demo")

@app.route('/')
def index():
    return render_template('index.html')

#route to accept the submitted form and validate it
@app.route('/register', methods=["POST"])
def register():
    is_valid = True
    #email validations
    if len(request.form["email"]) == 0:
        flash("Email field is required")
        is_valid = False
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid email")
        is_valid = False

    #first name validations
    if len(request.form["fname"]) < 0:
        flash("First name is required")
        is_valid = False
    elif not request.form["fname"].isalpha():
        flash("Invalid first name")
        is_valid = False
    
    #last name validations
    if len(request.form["lname"]) < 0:
        flash("Last name is required")
        is_valid = False
    elif not request.form["lname"].isalpha():
        flash("Invalid last name")
        is_valid = False

    #password validations
    if len(request.form["pw"]) < 8:
        flash("Password must be at least 8 characters")
        is_valid = False
    elif request.form["pw"] != request.form["confpw"]:
        flash("Passwords do not match")
        is_valid = False

    if is_valid:
        password = (request.form['pw'])
        salt = binascii.b2a_hex(os.urandom(15))
        hashed_pw = md5.new(password + salt).hexdigest()
        add_user = "INSERT INTO users (first_name, last_name, email, password, salt, created_at, updated_at) VALUES (:fn, :ln, :em, :hashed_pw, :salt, NOW(), NOW())"
        user_data = { 'fn': request.form["fname"],
                      'ln': request.form["lname"],
                      'em': request.form["email"],
                      'hashed_pw': hashed_pw,
                      'salt': salt}
        user_id = mysql.query_db(add_user, user_data)
        #set user in session
        session["name"] = request.form["fname"]
        session["user_id"] = user_id
        return redirect('/wall')
        
    return redirect('/')

@app.route('/login', methods=["POST"])
def login():
    #is there a user with that email in my db?
    find_user = "SELECT * FROM users WHERE email = :email"
    data = { 'email': request.form["email"]}
    found_user = mysql.query_db(find_user, data)

    #no user with that email
    if len(found_user) == 0:
        flash("No user registered with that email")
    else:
        #set user in session
        encrypted_password = md5.new(request.form["pw"] + found_user[0]['salt']).hexdigest()
        if found_user[0]["password"] == encrypted_password:
            flash("Thanks")
            session["name"] = found_user[0]["first_name"]
            session["user_id"] = found_user[0]["id"]
            return redirect('/wall')
        else:
            #if so, does the password they entered match what is in the db?
            flash("Your password did not match our records")    
    return redirect('/')

@app.route('/wall')
def show_wall():
    find_user = "SELECT * FROM messages"
    post_please = mysql.query_db(find_user)
    find_comment = 'SELECT * FROM comments'
    post_comment = mysql.query_db(find_comment)
    return render_template('wall.html', please=post_please, prettyplease=post_comment)

@app.route('/wall2', methods=['POST', 'GET'])
def wallpost():
    add_message = "INSERT INTO messages (message, created_at, updated_at, users_id) VALUES (:message, NOW(), NOW(), :users_id)"
    message_data = {'message': request.form['message'],
                    'users_id': session['user_id']}
    users_id = mysql.query_db(add_message, message_data)
    return redirect('/wall')

@app.route('/wall3', methods=['POST', 'GET'])
def wallcom():
    add_comment = "INSERT INTO comments (comment, created_at, updated_at, messages_id, users_id) VALUES (:comment, NOW(), NOW(), :messages_id, :users_id)"
    comment_data = {'comment': request.form['comment'],
                    'messages': session['message_id'],
                    'users': session['user_id']}          
    LordPlease=mysql.query_db(add_comment, comment_data)
    return redirect('/wall')



app.run(debug=True)