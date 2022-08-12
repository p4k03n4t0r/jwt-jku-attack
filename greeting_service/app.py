from flask import Flask, request
from jwcrypto import jwk, jwt, jws
import jwt as jpy
import requests
import json

app = Flask(__name__)

def is_authorized(user_request, role=None):
    token = user_request.headers.get("Authorization")
    if not token:
        return False

    token_header = jpy.get_unverified_header(token)
    if "jku" in token_header:
        response = requests.get(token_header.get("jku")).json()
        keyset = jwk.JWKSet.from_json(json.dumps(response))
        public_key = keyset.get_key(kid="MyKey")
        try:
            decoded_token = jwt.JWT(key=public_key, jwt=token)
        except jws.InvalidJWSSignature:
            return False
        if not role:
            return True

        json_decode = json.loads(decoded_token.claims)
        return json_decode.get("role") == role
    else:
        return False

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

if __name__ == "__main__":
    app.run(debug=True, port=6000)