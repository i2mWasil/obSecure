# routes/auth.py
from flask import Blueprint, request, jsonify, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import logging

from models import db, User, IdentityKey, SignedPrekey, OnetimePrekey
from utils.crypto_utils import CryptoUtils
from utils.phone_utils import PhoneUtils

auth_bp = Blueprint('auth', __name__)
limiter = Limiter(key_func=get_remote_address)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register_user():
    """Register a new user with mobile number and initial keys"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Validate required fields
        required_fields = ['phoneNumber', 'identityKey', 'signedPrekey', 'oneTimePrekeys']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        phone_number = data['phoneNumber']
        identity_key_data = data['identityKey']
        signed_prekey_data = data['signedPrekey']
        onetime_prekeys_data = data['oneTimePrekeys']
        
        # Validate phone number
        if not PhoneUtils.validate_phone_number(phone_number):
            return jsonify({'error': 'Invalid phone number format'}), 400
        
        # Normalize phone number
        phone_number = PhoneUtils.normalize_phone_number(phone_number)
        
        # Hash phone number
        phone_hash = CryptoUtils.hash_phone_number(phone_number)
        
        # Check if user already exists
        existing_user = User.query.filter_by(phone_number_hash=phone_hash).first()
        if existing_user:
            return jsonify({'error': 'User already exists'}), 409
        
        # Validate identity key structure
        if not all(key in identity_key_data for key in ['publicKey', 'signature']):
            return jsonify({'error': 'Invalid identity key structure'}), 400
        
        # Validate signed prekey structure
        if not all(key in signed_prekey_data for key in ['keyId', 'publicKey', 'signature']):
            return jsonify({'error': 'Invalid signed prekey structure'}), 400
        
        # Validate one-time prekeys
        if not isinstance(onetime_prekeys_data, list) or len(onetime_prekeys_data) == 0:
            return jsonify({'error': 'At least one one-time prekey required'}), 400
        
        # Begin transaction
        try:
            # Create user
            user = User(phone_number_hash=phone_hash)
            db.session.add(user)
            db.session.flush()  # Get user ID
            
            # Store identity key
            identity_key = IdentityKey(
                user_id=user.id,
                public_key=identity_key_data['publicKey'],
                key_signature=identity_key_data['signature']
            )
            db.session.add(identity_key)
            
            # Store signed prekey
            signed_prekey = SignedPrekey(
                user_id=user.id,
                key_id=signed_prekey_data['keyId'],
                public_key=signed_prekey_data['publicKey'],
                signature=signed_prekey_data['signature']
            )
            db.session.add(signed_prekey)
            
            # Store one-time prekeys
            for otk_data in onetime_prekeys_data:
                if not all(key in otk_data for key in ['keyId', 'publicKey']):
                    return jsonify({'error': 'Invalid one-time prekey structure'}), 400
                
                otk = OnetimePrekey(
                    user_id=user.id,
                    key_id=otk_data['keyId'],
                    public_key=otk_data['publicKey']
                )
                db.session.add(otk)
            
            db.session.commit()
            
            logger.info(f"User registered successfully: {phone_hash[:8]}...")
            
            return jsonify({
                'success': True,
                'userId': str(user.id),
                'message': 'User registered successfully'
            }), 201
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration transaction failed: {str(e)}")
            raise
            
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/verify-phone', methods=['POST'])
@limiter.limit("10 per minute")
def verify_phone():
    """Verify phone number exists in system"""
    try:
        data = request.get_json()
        
        if not data or 'phoneNumber' not in data:
            return jsonify({'error': 'Phone number required'}), 400
        
        phone_number = data['phoneNumber']
        
        if not PhoneUtils.validate_phone_number(phone_number):
            return jsonify({'error': 'Invalid phone number format'}), 400
        
        phone_number = PhoneUtils.normalize_phone_number(phone_number)
        phone_hash = CryptoUtils.hash_phone_number(phone_number)
        
        user = User.query.filter_by(phone_number_hash=phone_hash).first()
        
        return jsonify({
            'exists': user is not None,
            'active': user.is_active if user else False
        })
        
    except Exception as e:
        logger.error(f"Phone verification error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
