import subprocess
from flask import Flask, render_template, request, redirect, session, url_for, escape
import hashlib
import os

app = Flask(__name__)

app.secret_key = b'\x93:\x05iT\xa6\x8c\x18T\x88h\x01\xc6\xda\xf3\x19'

logins = {}

DICTFILE = "static/wordlist.txt"

def hashit(key):
    m = hashlib.sha256()
    m.update(key.encode())
    return m.digest()

def checkit(hash2compare, key):
    return hash2compare == hashit(key)


def validate_login(username, password, auth):
    try:
        if username not in logins: return 1

        if not checkit(logins[username]['password'], password): return 1

        if not checkit(logins[username]['auth'], auth): return 2

    except KeyError:
        return -1
    
    return 0


def register_login(username, password, auth):

    try:
        if username in logins: return 1

        logins[username] = {}
        logins[username]['password'] = hashit(password)
        logins[username]['auth'] = hashit(auth)

    except KeyError:
        return -1

    return 0



@app.route("/")
def home():
    return render_template('home.html')

@app.route("/register", methods=['POST', 'GET'])
def register():
    error = None
    if request.method == 'POST':
     
        status = register_login(request.form['username'], request.form['password'], request.form['auth'])
        if status == 0:
            return render_template('home.html')
        elif status == 1:
            error = 'Invalid Registration'
        else:
            error = 'System Error'
     
    return render_template('register.html', error=error)

@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    if request.method == 'POST':
        status = validate_login(request.form['username'], request.form['password'], request.form['auth'])
        if status == 0:
            session['username'] = request.form['username']
            return redirect('/spell_check')

        elif status == 1:
            error = 'Invalid username/password'
        elif status == 2:
            error = '2fa'
        else:
            error = 'System Error'

    return render_template('login.html', error=error)


@app.route("/spell_check" , methods=['POST', 'GET'])
def spell_check():
    if 'username' in session:
        print("in spell check")
        textout = None
        misspelled = None
        if request.method == 'POST':
            textout = request.form['inputtext']
            print(request.form['inputtext'])
            print("got textout" + str(textout))

            textfile = 'static/textout.txt'
            with open(textfile, 'w+') as f:
                f.write(textout)

            # this subprocess call is mostly from the assignment one autograder
            progout = subprocess.Popen(["./static/a.out", textfile, DICTFILE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            misspelled = progout.stdout.read().decode().strip().split('\n')

            print(misspelled)

            f.close()
            os.remove(textfile)
        
            return render_template('spell_check.html', textout=textout, misspelled=misspelled)
        
        
        return render_template('spell_check.html')


    return redirect('/login')

        
@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return render_template('home.html')
    
if __name__ == "__main__":
    app.run(debug=True)