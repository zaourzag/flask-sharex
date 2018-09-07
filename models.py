import time
import hashlib


class User:
    def __init__(self, **data):
        self.uid = data.get("uid")
        self.name = data.get("name")
        self.token = data.get("token")
        self.password = data.get("password")

    @classmethod
    def make(cls, uid, name, token, password):
        return cls(**{"uid": uid, "name": name, "token": token, "password": hashlib.sha256(password.encode('utf-8')).hexdigest()})


class SFile:
    def __init__(self, **data):
        self.name = data.get("name")
        self.extension = data.get("extension")
        self.user_uid = data.get("user_uid")
        self.created = data.get("created", time.time() * 1000)
        self.ip = data.get("ip", "unknown")

    @classmethod
    def make(cls, filename: str, extension: str, user_uid: int, ip: str):
        return cls(**{"name": filename, "extension": extension, "user_uid": user_uid, "ip": ip})
