import time


class User:
    def __init__(self, **data):
        self.uid = data.get("uid")
        self.name = data.get("name")
        self.token = data.get("token")

    @classmethod
    def make(cls, uid, name, token):
        return cls(**{"uid": uid, "name": name, "token": token})


class SFile:
    def __init__(self, **data):
        self.name = data.get("name")
        self.extension = data.get("extension")
        self.user_uid = data.get("user_uid")
        self.created = data.get("created", time.time() * 1000)

    @classmethod
    def make(cls, filename: str, extension: str, user_uid: int):
        return cls(**{"name": filename, "extension": extension, "user_id": user_uid})
