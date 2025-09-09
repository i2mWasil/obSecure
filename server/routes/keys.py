# routes/keys.py
from flask import Blueprint, request, jsonify, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import logging

from models import db, User, IdentityKey, SignedPrekey, OnetimePrekey
from utils.crypto_utils import CryptoUtils
from utils.phone_utils import PhoneUtils

keys_bp = Blueprint('keys', __name__)
limiter = Limiter(key_func=get_remote_address)

logger = logging.getLogger(__name__)

@keys_bp.route('/keybundle', methods=['POST'])
@limiter.limit("20 per minute")
def get_key_bundle():
    """Get key bundle for X3DH initialization"""
    try:
        data = request.get_json()
        
        if not data or 'phoneNumber' not in data:
            return jsonify({'error': 'Phone number required'}), 400
        
        phone_number = data['phoneNumber']
        
        if not PhoneUtils.validate_phone_number(phone_number):
            return jsonify({'error': 'Invalid phone number format'}), 400
        
        phone_number = PhoneUtils.normalize_phone_number(phone_number)
        phone_hash = CryptoUtils.hash_phone_number(phone_number)
        
        # Get user
        user = User.query.filter_by(phone_number_hash=phone_hash).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not user.is_active:
            return jsonify({'error': 'User account is inactive'}), 403
        
        # Get identity key
        identity_key = IdentityKey.query.filter_by(
            user_id=user.id, 
            is_active=True
        ).order_by(IdentityKey.created_at.desc()).first()
        
        if not identity_key:
            return jsonify({'error': 'Identity key not found'}), 404
        
        # Get active signed prekey
        signed_prekey = SignedPrekey.query.filter(
            SignedPrekey.user_id == user.id,
            SignedPrekey.is_active == True,
            SignedPrekey.expires_at > datetime.utcnow()
        ).order_by(SignedPrekey.created_at.desc()).first()
        
        if not signed_prekey:
            return jsonify({'error': 'Valid signed prekey not found'}), 404
        
        # Get and mark one-time prekey as used (atomic operation)
        onetime_prekey = None
        try:
            # Use database-level locking to prevent race conditions
            otk = OnetimePrekey.query.filter_by(
                user_id=user.id,
                is_used=False
            ).order_by(OnetimePrekey.created_at).with_for_update().first()
            
            if otk:
                otk.is_used = True
                otk.used_at = datetime.utcnow()
                onetime_prekey = {
                    'keyId': otk.key_id,
                    'publicKey': otk.public_key
                }
                db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error marking OTK as used: {str(e)}")
        
        # Build key bundle
        key_bundle = {
            'identityKey': {
                'publicKey': identity_key.public_key,
                'signature': identity_key.key_signature
            },
            'signedPrekey': {
                'keyId': signed_prekey.key_id,
                'publicKey': signed_prekey.public_key,
                'signature': signed_prekey.signature
            }
        }
        
        if onetime_prekey:
            key_bundle['oneTimePrekey'] = onetime_prekey
        
        # Update user last active time
        user.last_active = datetime.utcnow()
        db.session.commit()
        
        return jsonify(key_bundle)
        
    except Exception as e:
        logger.error(f"Key bundle error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@keys_bp.route('/upload-otks', methods=['POST'])
@limiter.limit("10 per hour")
def upload_onetime_prekeys():
    """Upload new one-time prekeys"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        required_fields = ['phoneNumber', 'oneTimePrekeys']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        phone_number = data['phoneNumber']
        onetime_prekeys_data = data['oneTimePrekeys']
        
        if not PhoneUtils.validate_phone_number(phone_number):
            return jsonify({'error': 'Invalid phone number format'}), 400
        
        if not isinstance(onetime_prekeys_data, list) or len(onetime_prekeys_data) == 0:
            return jsonify({'error': 'At least one one-time prekey required'}), 400
        
        if len(onetime_prekeys_data) > 100:
            return jsonify({'error': 'Maximum 100 one-time prekeys per upload'}), 400
        
        phone_number = PhoneUtils.normalize_phone_number(phone_number)
        phone_hash = CryptoUtils.hash_phone_number(phone_number)
        
        # Get user
        user = User.query.filter_by(phone_number_hash=phone_hash).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not user.is_active:
            return jsonify({'error': 'User account is inactive'}), 403
        
        # Check current OTK count
        current_otk_count = OnetimePrekey.query.filter_by(
            user_id=user.id,
            is_used=False
        ).count()
        
        if current_otk_count > 500:
            return jsonify({'error': 'Too many unused one-time prekeys'}), 400
        
        # Add new one-time prekeys
        try:
            uploaded_count = 0
            for otk_data in onetime_prekeys_data:
                if not all(key in otk_data for key in ['keyId', 'publicKey']):
                    continue
                
                # Check for duplicate key IDs
                existing_otk = OnetimePrekey.query.filter_by(
                    user_id=user.id,
                    key_id=otk_data['keyId']
                ).first()
                
                if existing_otk:
                    continue  # Skip duplicate
                
                otk = OnetimePrekey(
                    user_id=user.id,
                    key_id=otk_data['keyId'],
                    public_key=otk_data['publicKey']
                )
                db.session.add(otk)
                uploaded_count += 1
            
            db.session.commit()
            
            logger.info(f"Uploaded {uploaded_count} OTKs for user: {phone_hash[:8]}...")
            
            return jsonify({
                'success': True,
                'uploaded': uploaded_count,
                'total_unused': current_otk_count + uploaded_count
            })
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"OTK upload transaction failed: {str(e)}")
            raise
            
    except Exception as e:
        logger.error(f"OTK upload error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@keys_bp.route('/rotate-signed-prekey', methods=['POST'])
@limiter.limit("5 per hour")
def rotate_signed_prekey():
    """Rotate signed prekey"""
    try:
        data = request.get_json()
        
        required_fields = ['phoneNumber', 'newSignedPrekey']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        phone_number = data['phoneNumber']
        new_signed_prekey_data = data['newSignedPrekey']
        
        if not PhoneUtils.validate_phone_number(phone_number):
            return jsonify({'error': 'Invalid phone number format'}), 400
        
        if not all(key in new_signed_prekey_data for key in ['keyId', 'publicKey', 'signature']):
            return jsonify({'error': 'Invalid signed prekey structure'}), 400
        
        phone_number = PhoneUtils.normalize_phone_number(phone_number)
        phone_hash = CryptoUtils.hash_phone_number(phone_number)
        
        user = User.query.filter_by(phone_number_hash=phone_hash).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        try:
            # Deactivate old signed prekeys
            SignedPrekey.query.filter_by(
                user_id=user.id,
                is_active=True
            ).update({'is_active': False})
            
            # Add new signed prekey
            new_signed_prekey = SignedPrekey(
                user_id=user.id,
                key_id=new_signed_prekey_data['keyId'],
                public_key=new_signed_prekey_data['publicKey'],
                signature=new_signed_prekey_data['signature']
            )
            db.session.add(new_signed_prekey)
            
            user.last_active = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Signed prekey rotated for user: {phone_hash[:8]}...")
            
            return jsonify({
                'success': True,
                'message': 'Signed prekey rotated successfully'
            })
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Signed prekey rotation failed: {str(e)}")
            raise
            
    except Exception as e:
        logger.error(f"Signed prekey rotation error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@keys_bp.route('/key-stats', methods=['POST'])
@limiter.limit("30 per minute")
def get_key_statistics():
    """Get key statistics for user"""
    try:
        data = request.get_json()
        
        if not data or 'phoneNumber' not in data:
            return jsonify({'error': 'Phone number required'}), 400
        
        phone_number = PhoneUtils.normalize_phone_number(data['phoneNumber'])
        phone_hash = CryptoUtils.hash_phone_number(phone_number)
        
        user = User.query.filter_by(phone_number_hash=phone_hash).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get statistics
        identity_keys_count = IdentityKey.query.filter_by(
            user_id=user.id,
            is_active=True
        ).count()
        
        signed_prekeys_count = SignedPrekey.query.filter(
            SignedPrekey.user_id == user.id,
            SignedPrekey.is_active == True,
            SignedPrekey.expires_at > datetime.utcnow()
        ).count()
        
        unused_otks_count = OnetimePrekey.query.filter_by(
            user_id=user.id,
            is_used=False
        ).count()
        
        used_otks_count = OnetimePrekey.query.filter_by(
            user_id=user.id,
            is_used=True
        ).count()
        
        return jsonify({
            'identityKeys': identity_keys_count,
            'activeSignedPrekeys': signed_prekeys_count,
            'unusedOneTimePrekeys': unused_otks_count,
            'usedOneTimePrekeys': used_otks_count,
            'lastActive': user.last_active.isoformat() if user.last_active else None
        })
        
    except Exception as e:
        logger.error(f"Key stats error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
