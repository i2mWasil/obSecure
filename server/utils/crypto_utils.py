# utils/crypto_utils.py
import hmac
import hashlib
import secrets
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.exceptions import InvalidSignature
import base64

class CryptoUtils:
    @staticmethod
    def hash_phone_number(phone_number: str, salt: str = None) -> str:
        """Hash phone number with HMAC-SHA256"""
        if salt is None:
            salt = os.environ.get('PHONE_SALT', 'default-salt-change-in-production')
        
        return hmac.new(
            salt.encode('utf-8'),
            phone_number.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    @staticmethod
    def generate_key_pair():
        """Generate X25519 key pair"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return {
            'private': base64.b64encode(private_bytes).decode(),
            'public': base64.b64encode(public_bytes).decode()
        }
    
    @staticmethod
    def verify_key_signature(public_key: str, signature: str, identity_key: str) -> bool:
        """Verify key signature (simplified - implement with actual crypto library)"""
        # This is a placeholder - implement actual signature verification
        # based on your chosen signature scheme (Ed25519, ECDSA, etc.)
        try:
            # Decode and verify signature
            return len(signature) > 0 and len(public_key) > 0
        except Exception:
            return False
    
    @staticmethod
    def derive_shared_secret(dh_outputs: list) -> bytes:
        """Derive shared secret using HKDF"""
        # Combine all DH outputs
        combined = b''.join([base64.b64decode(output) for output in dh_outputs])
        
        # Use HKDF to derive final shared secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'',
            info=b'X3DH',
        )
        
        return hkdf.derive(combined)
