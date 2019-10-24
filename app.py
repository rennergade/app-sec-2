import subprocess
from flask import Flask, render_template, request, redirect, session, url_for, escape
import hashlib
import bleach
import os
from flask_wtf.csrf import CSRFProtect


def create_app(config=None):
    app = Flask(__name__)

    app.secret_key = os.urandom(16)

    # using flask_wtf for csrf protection
    csrf = CSRFProtect(app)

    logins = {}

    DICTFILE = "wordlist.txt"

    # shashing our passwords!
    def hashit(key):
        m = hashlib.sha256()
        m.update(key.encode())
        return m.digest()

    # and checking them too!
    def checkit(hash2compare, key):
        return hash2compare == hashit(key)


    def validate_login(username, password, auth):
        try:
            if username not in logins: return 1
            # differentiate via password and 2fa failure
            if not checkit(logins[username]['password'], password): return 1

            if not checkit(logins[username]['auth'], auth): return 2

        except KeyError:
            return -1
        
        return 0


    def register_login(username, password, auth):

        try:
            # we want our usernames to not already be there, and we also want our fields to be populated!
            if username in logins: return 1
            if not len(username) or not len(password) or not len(auth): return 1

            # add user and hashed fields
            logins[username] = {}
            logins[username]['password'] = hashit(password)
            logins[username]['auth'] = hashit(auth)

        except KeyError:
            return -1

        return 0



    @app.route("/")
    def home():
        loggedin = False
        if 'username' in session: loggedin = True
        return render_template('home.html', loggedin=loggedin)

    @app.route("/register", methods=['POST', 'GET'])
    def register():
        success = None
        loggedin = False
        if 'username' in session: loggedin = True
        if request.method == 'POST':
            bleached_uname = bleach.clean(request.form['username'])
            bleached_pass = bleach.clean(request.form['password'])
            bleached_auth = bleach.clean(request.form['username'])
        
            status = register_login(bleached_uname, bleached_pass, bleached_auth)
            if status == 0:
                success = 'Registration Success'
            elif status == 1:
                success = 'Error Invalid Registration'
            else:
                success = 'System Error'
        
        return render_template('register.html', id=success, loggedin=loggedin)

    @app.route('/login', methods=['POST', 'GET'])
    def login():
        result = None
        loggedin = False
        if 'username' in session: loggedin = True

        if request.method == 'POST':
            # bleach all input fileds to mediate XSS
            bleached_uname = bleach.clean(request.form['username'])
            bleached_pass = bleach.clean(request.form['password'])
            bleached_auth = bleach.clean(request.form['username'])

            status = validate_login(bleached_uname, bleached_pass, bleached_auth)
            if status == 0:
                result = 'Success'
                session['username'] = bleached_uname
                loggedin = True
            elif status == 1:
                result = 'Invalid username/password'
            elif status == 2:
                result = '2fa'
            else:
                result = 'System Error'

        return render_template('login.html', id=result, loggedin=loggedin)


    @app.route("/spell_check" , methods=['POST', 'GET'])
    def spell_check():
        loggedin=False
        # using flask 'session' for session hijacking
        if 'username' in session:
            loggedin = True
            textout = None
            misspelled = None

            if request.method == 'POST':
                textout = bleach.clean(request.form['inputtext'])
    
                # we've got to write the text to a file for the checker to work (takes file input)
                textfile = 'textout.txt'
                with open(textfile, 'w+') as f:
                    f.write(textout)

                # this subprocess call is mostly from the assignment one autograder
                progout = subprocess.Popen(["./a.out", textfile, DICTFILE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                misspelled = progout.stdout.read().decode().strip().split('\n')

                f.close()
                os.remove(textfile)
            
                return render_template('spell_check.html', textout=textout, misspelled=misspelled, loggedin=loggedin)
            
            
            return render_template('spell_check.html', loggedin=loggedin)


        return redirect('/login')

            
    @app.route('/logout')
    def logout():
        session.pop('username', None)
        return render_template('home.html')


    return app
    
if __name__ == "__main__":
    app.create_app()