import datetime
import hashlib
import os
import secrets
import traceback
from os.path import splitext
from werkzeug.utils import secure_filename

import pymongo
from PIL import Image
from flask import Flask, request, json, jsonify, render_template, session, redirect, send_from_directory
from flask_session import Session
from pymongo import MongoClient

from models import User, SFile

_config = json.load(open("./config.json", 'r'))
storage_folder = _config['storage_dir']
secret_key = _config['api_secret']
app_secret = _config['app_secret']
allowed_extension = _config['allowed_extensions']
image_extension = _config['image_extensions']
allowed_domains = _config['domains']

app = Flask(__name__)
app.secret_key = app_secret.encode("utf-8")
SESSION_TYPE = 'redis'
SESSION_USE_SIGNER = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
app.config.from_object(__name__)
Session(app)

_mongo = MongoClient(_config['mongo_ip'], _config['mongo_port'])
_db = _mongo["sharex-server"]


def get_client_ip():
    x_forwarded_for = request.environ.get('HTTP_X_FORWARDED_FOR')
    cd_orig_ip = request.environ.get('HTTP_CF_CONNECTING_IP')
    if cd_orig_ip:
        ip = cd_orig_ip
    elif x_forwarded_for:
        ip = x_forwarded_for.split(',')[-1]
        ip = ip.replace(' ', '')
    else:
        ip = request.environ.get('REMOTE_ADDR')
    return ip


def check_token(token):
    user = _db.users.find_one({"token": token})
    if user:
        return User(**user)
    else:
        return None


def check_user(username, password):
    pwd = hashlib.sha256(password.encode('utf-8')).hexdigest()
    user = _db.users.find_one({"name": username, "password": pwd})
    if user:
        return User(**user)
    else:
        return None


def create_new_file(filename, ext, user: User, ip):
    try:
        _db.images.insert_one(SFile.make(filename, ext, user.uid, ip).__dict__)
    except Exception as e:
        print(e)


def create_new_user(uid: int, name: str):
    token = secrets.token_urlsafe(64)
    password = secrets.token_urlsafe(6)
    try:
        _db.users.insert_one(User.make(uid, name, token, password).__dict__)
        return token, password
    except Exception as e:
        print(traceback.format_exc())
        return str(e), "Rip"


@app.template_filter('getdate')
def datefromunix(s):
    return datetime.datetime.fromtimestamp(int(s) / 1000).strftime("%Y-%m-%d %H:%M")

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                     'favicon.ico', mimetype='image/vnd.microsoft.icon')



@app.route('/')
def index():
    return render_template("home.html", domains=allowed_domains)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        usr = check_user(request.form.get("username", "unknown"), request.form.get("password", "unknown"))
        if usr is None:
            return render_template('login.html', is_error=True)
        next_url = request.args.get("next", "/")
        if session.get("logged_in"):
            return redirect(next_url)
        session['logged_in'] = usr.uid
        return redirect(next_url)

    else:
        return render_template('login.html', is_error=False)


@app.route('/my/ip', methods=['GET'])
def my_ip():
    return jsonify({"ip": get_client_ip()})


@app.route('/my', methods=['GET'])
def my_portal():
    if session.get("logged_in", None) is None:
        return redirect("/login?next=/my")
    total = _db.images.find({"user_uid": session.get("logged_in")}).count()
    activity = _db.images.find({"user_uid": session.get("logged_in")}).sort('created', pymongo.DESCENDING).limit(5)
    activity = [x for x in activity]
    return render_template("my_portal.html", domains=allowed_domains, total=total, images=activity)
@app.route('/i/<filename>')
def return_pic(filename):
    """ Show just the image specified.
    """
    return send_from_directory( _config['storage_dir'], secure_filename(filename))

@app.route('/my/files', methods=['GET', 'POST'])
def my_files():
    if session.get("logged_in", None) is None:
        return redirect("/login?next=/my/files")

    if request.method == "POST":
        action = request.form.get("action")
        if action == "delete_all":
            total = _db.images.find({"user_uid": session.get("logged_in")})
            for image in total:
                fpath = "{}/{}{}".format(storage_folder, image['name'], image['extension'])
                if os.path.exists(fpath):
                    os.remove(fpath)
                else:
                    print("This file does not exist:", fpath)
            _db.images.delete_many({"user_uid": session.get("logged_in")})
        elif action == "delete_one":
            name = request.form.get("name")
            image = _db.images.find_one({"user_uid": session.get("logged_in"), "name": name})
            if image:
                fpath = "{}/{}{}".format(storage_folder, image['name'], image['extension'])
                if os.path.exists(fpath):
                    os.remove(fpath)
                else:
                    print("This file does not exist:", fpath)
                    return jsonify({"success": False})
                _db.images.delete_one({"user_uid": session.get("logged_in"), "name": image['name']})
        return jsonify({"success": True})

    def get_page(page_size, page_num):
        skips = page_size * (page_num - 1)
        cursor = _db.images.find({"user_uid": session.get("logged_in")}) \
            .skip(skips) \
            .limit(page_size) \
            .sort('created', pymongo.DESCENDING)
        return [x for x in cursor]

    page = int(request.args.get("page", 1))
    images = get_page(50, page)
    next_page = bool(get_page(50, page + 1))
    next_page_num = page + 1
    prev_page = page != 1
    prev_page_num = page - 1

    return render_template("my_files.html", images=images, page=page, next_page=next_page, prev_page=prev_page,
                           next_page_num=next_page_num, prev_page_num=prev_page_num)


@app.route('/my/config', methods=['GET'])
def my_config():
    if session.get("logged_in", None) is None:
        return redirect("/login?next=/my/config")
    usr = _db.users.find_one({"uid": session.get("logged_in")})
    return render_template("my_config.html", **{"domains": allowed_domains, "token": usr['token']})


@app.route('/domains', methods=['GET'])
def print_domains():
    return jsonify({"domains": allowed_domains})


@app.route('/stats', methods=['GET'])
def print_stats():
    if session.get("logged_in", None) is None:
        return redirect("/login?next=/stats")
    return jsonify({
        "users": _db.users.count(),
        "files": _db.images.count(),
        "domains": len(allowed_domains)
    })


@app.route('/upload', methods=['POST'])
def upload():
    user = check_token(request.headers.get("Authorization", "unknown"))
    if user is None:
        return "Not authorized", 403
    if request.method == 'POST':
        '''Get file object from POST request, extract and define needed variables for future use.'''
        file = request.files['image']
        extension = splitext(file.filename)[1]
        file.flush()
        size = os.fstat(file.fileno()).st_size
        '''Check for file extension and file size.'''
        if extension not in allowed_extension:
            return 'File type is not supported', 415

        elif size > 20000000:
            return 'File size too large', 400

        elif extension in image_extension:
            '''Remove metadata of the file.'''
            image = Image.open(file)
            data = list(image.getdata())
            file_without_exif = Image.new(image.mode, image.size)
            file_without_exif.putdata(data)

            '''Save the image with a new randomly generated filename in the desired path, and return URL info.'''
            filename = secrets.token_urlsafe(10)
            file_without_exif.save(os.path.join(storage_folder, filename + extension))
            create_new_file(filename, extension, user, get_client_ip())
            return jsonify({"filename": filename, "extension": extension}), 200
        else:
            filename = secrets.token_urlsafe(8)
            file.save(os.path.join(storage_folder, filename + extension))
            create_new_file(filename, extension, user, get_client_ip())
            return jsonify({"filename": filename, "extension": extension}), 200


@app.route('/add-user', methods=['POST'])
def add_user():
    token = request.headers.get("Authorization", "unknown")
    if token != secret_key:
        return "Not authorized", 403
    if request.method == 'POST':
        user_id = request.form['uid']
        user_name = request.form['name']
        check_existing = _db.users.find_one({"uid": user_id})
        if not check_existing:
            new_token, password = create_new_user(user_id, user_name)
            return jsonify({"token": new_token, "password": password})
        else:
            return "Already exists", 409


if __name__ == '__main__':
    app.run(port=80)
