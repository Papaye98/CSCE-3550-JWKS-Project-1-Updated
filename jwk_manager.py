import json
import time
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class JWKManager:
    def __init__(self):
        self.keys = {}
    
    def generate_key(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = str(int(time.time()))
        expiry = time.time() + 86400  # 1 day expiry

        private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        jwk = {
            'kid': kid,
            'expiry': expiry,
            'private_key': private_key,
            'public_key': public_key
        }

        self.keys[kid] = jwk
        return jwk

    def get_jwks(self):
        return [
            {'kid': kid, 'key': jwk['public_key'].decode('utf-8')}
            for kid, jwk in self.keys.items() if jwk['expiry'] > time.time()
        ]

    def get_key_by_kid(self, kid):
        return self.keys.get(kid)

jwk_manager = JWKManager()
