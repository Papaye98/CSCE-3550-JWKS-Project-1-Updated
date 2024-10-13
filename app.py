from flask import Flask, jsonify, request
import jwt
import time
from jwk_manager import jwk_manager

app = Flask(__name__)

# JWKS endpoint
@app.route('/jwks', methods=['GET'])
def jwks():
    return jsonify({"keys": jwk_manager.get_jwks()}), 200

# Auth endpoint to issue a JWT
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired', 'false') == 'true'
    kid = list(jwk_manager.keys.keys())[0]  # Use first key for simplicity
    jwk = jwk_manager.get_key_by_kid(kid)

    if expired:
        expiry_time = time.time() - 3600  # Issue with past expiry
    else:
        expiry_time = time.time() + 3600  # Valid for 1 hour

    token = jwt.encode(
        {
            'sub': 'user_id',
            'exp': expiry_time,
            'kid': kid
        },
        jwk['private_key'],
        algorithm='RS256'
    )

    return jsonify({"token": token}), 200

if __name__ == '__main__':
    # Generate an RSA key on startup
    jwk_manager.generate_key()
    app.run(host='0.0.0.0', port=8080)
