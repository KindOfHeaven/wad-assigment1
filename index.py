from flask import Flask, render_template, flash, request, redirect, send_from_directory, make_response
from pymongo import MongoClient

import hashlib
import hmac

client = MongoClient('localhost', 27017)
db = client.assignment1

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['UPLOAD_FOLDER'] = './uploaded/'

SECRET_KEY = b"s3cr3ts4lt"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'svg'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/cabinet')
def cabinet():
    username = request.cookies.get('username')
    token = request.cookies.get('token')

    if not hmac.compare_digest(
        hmac.new(SECRET_KEY, username.encode(), hashlib.sha256).hexdigest(),
        token
    ):
        return render_template('error.html', error = 'Forbidden 403')
    return render_template('cabinet.html', username = username)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        passwordHash = hmac.new(SECRET_KEY, password.encode(), hashlib.sha256).hexdigest()
        if (db.users.find_one({ 'username': username })):
            flash(f'The user with this username already exists!')
            return redirect('/signup')
        else:
            document = {
                'username': username,
                'password': passwordHash
            }

            db.users.insert_one(document)
            return render_template('signup-thanks.html', username = username)
    else:
        return render_template('signup.html')

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        passwordHash = hmac.new(SECRET_KEY, password.encode(), hashlib.sha256).hexdigest()

        user = db.users.find_one({ 'username': username })

        if (user and hmac.compare_digest(passwordHash, user['password'])):
            resp = make_response(redirect(url_for('cabinet')))
            resp.set_cookie('username', username)
            resp.set_cookie('token', hmac.new(SECRET_KEY, username.encode(), hashlib.sha256).hexdigest())
            return resp
        else:
            flash(f'Invalid credentials!')
        return redirect('/auth')
    else:
        return render_template('auth.html')

@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.set_cookie('username', '')
    resp.set_cookie('token', '')
    return resp


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']

        if file.filename == '':
            flash('No selected file!')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('Invalid file extension!')
            return redirect(request.url)

        file.save(app.config['UPLOAD_FOLDER'] + file.filename)
        return redirect('/uploaded/' + file.filename)
    else:  
        username = request.cookies.get('username')
        token = request.cookies.get('token')

        if not hmac.compare_digest(
            hmac.new(SECRET_KEY, username.encode(), hashlib.sha256).hexdigest(),
            token
        ):
            return render_template('error.html', error = 'Forbidden 403')

        return render_template('upload.html', username = username)    
        
       
@app.route('/uploaded/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

app.run(host="localhost", port="5001", debug=True)