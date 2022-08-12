from flask import Flask, request
from jwcrypto import jwk, jwt, jws
import jwt as jpy
import requests
import json
from password import generate_password

KEY_PAIR:jwk.JWK = None
USERS = {"admin": generate_password(50)}

app = Flask(__name__)

def init_key_pair():
    global KEY_PAIR
    KEY_PAIR = jwk.JWK.generate(kty="RSA", size=2048)

def is_authorized(user_request, role=None):
    token = user_request.headers.get("Authorization")
    if not token:
        return False

    token_header = jpy.get_unverified_header(token)
    if "jku" in token_header:
        response = requests.get(token_header.get("jku")).json()
        keyset = jwk.JWKSet.from_json(json.dumps(response))
        my_key = keyset.get_key(kid="MyKey")
        try:
            decoded_token = jwt.JWT(key=my_key, jwt=token)
        except jws.InvalidJWSSignature:
            return False
        if not role:
            return True

        json_decode = json.loads(decoded_token.claims)
        return json_decode.get("role") == role
    else:
        return False


@app.route("/register", methods=["POST"])
def register():
    if "username" not in request.get_json() and "password" not in request.get_json():
        return {"error": "Fields 'username' and 'password' must be supplied"}, 400
    username = request.get_json()["username"]
    password = request.get_json()["password"]
    if username in USERS:
        return {"error": "User already registered"}, 400
    USERS[username] = password
    return {"message": "Welcome!"}, 200

@app.route("/login", methods=["POST"])
def login():
    if "username" not in request.get_json() and "password" not in request.get_json():
        return {"error": "Fields 'username' and 'password' must be supplied"}, 400
    username = request.get_json()["username"]
    password = request.get_json()["password"]
    if username not in USERS or password != USERS[username]:
        return {"error": "Invalid credentials"}, 400

    role = "admin" if username == "admin" else "user"

    token = jwt.JWT(header={"alg": "RS256", "jku": "http://localhost:5000/public_key"}, claims={"role":role})
    token.make_signed_token(KEY_PAIR)
    return {"token": token.serialize()}, 200

@app.route("/greeting", methods=["GET"])
def greeting():
    if not is_authorized(request):
        return {"error": "Unauthorized"}, 401
    return {"greeting":"Hello world"}, 200

@app.route("/secret_greeting", methods=["GET"])
def secret_greeting():
    if not is_authorized(request, "admin"):
        return {"error": "Unauthorized"}, 401
    return {"greeting":open("TOP_SECRET.txt").read()}, 200

@app.route("/public_key", methods=["GET"])
def public_key():
    pub_key = json.loads(KEY_PAIR.export_public())
    pub_key["use"] = "sig"
    pub_key["kid"] = "MyKey"
    pub_key["alg"] = "RS256"
    return {"keys": [pub_key]}, 200

if __name__ == "__main__":
    init_key_pair()
    app.run(debug=True)