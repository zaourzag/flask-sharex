import json
import os
import secrets
from os.path import splitext

from PIL import Image
from flask import Flask, request, json
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
_mongo = MongoClient(_config['mongo_ip'], _config['mongo_port'])
_db = _mongo["sharex-server"]


def check_token(token):
    user = _db.users.find_one({"token": token})
    if user:
        return User(**user)
    else:
        return None


def create_new_file(filename, ext, user: User):
    try:
        _db.images.insert_one(dict(SFile.make(filename, ext, user.uid)))
    except Exception as e:
        print(e)


def create_new_user(uid: int, name: str):
    token = secrets.token_urlsafe(64)
    try:
        _db.user.insert_one(dict(User.make(uid, name, token)))
        return token
    except Exception as e:
        print(e)
        return None


@app.route('/domains', methods=['GET'])
def print_domains():
    return json.dumps({"domains": allowed_domains})


@app.route('/stats', methods=['GET'])
def print_stats():
    return json.dumps({
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

        elif size > 6000000:
            return 'File size too large', 400

        elif extension in image_extension:
            '''Remove metadata of the file.'''
            image = Image.open(file)
            data = list(image.getdata())
            file_without_exif = Image.new(image.mode, image.size)
            file_without_exif.putdata(data)

            '''Save the image with a new randomly generated filename in the desired path, and return URL info.'''
            filename = secrets.token_urlsafe(12)
            file_without_exif.save(os.path.join(storage_folder, filename + extension))
            create_new_file(filename, extension, user)
            return json.dumps({"filename": filename, "extension": extension}), 200
        else:
            filename = secrets.token_urlsafe(8)
            file.save(os.path.join(storage_folder, filename + extension))
            create_new_file(filename, extension, user)
            return json.dumps({"filename": filename, "extension": extension}), 200


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
            new_token = create_new_user(user_id, user_name)
            return json.dumps({"token": new_token})
        else:
            return "Already exists", 409


if __name__ == '__main__':
    app.run(port=80)
