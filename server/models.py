# models.py
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timedelta
import uuid

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    phone_number_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    identity_keys = db.relationship('IdentityKey', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    signed_prekeys = db.relationship('SignedPrekey', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    onetime_prekeys = db.relationship('OnetimePrekey', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.id}>'

class IdentityKey(db.Model):
    __tablename__ = 'identity_keys'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    key_signature = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    __table_args__ = (
        db.Index('idx_identity_keys_user_active', 'user_id', 'is_active'),
    )

class SignedPrekey(db.Model):
    __tablename__ = 'signed_prekeys'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    key_id = db.Column(db.Integer, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    __table_args__ = (
        db.Index('idx_signed_prekeys_user_active', 'user_id', 'is_active', 'expires_at'),
        db.UniqueConstraint('user_id', 'key_id', name='_user_key_id_uc'),
    )
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.expires_at:
            self.expires_at = datetime.utcnow() + timedelta(days=7)

class OnetimePrekey(db.Model):
    __tablename__ = 'onetime_prekeys'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    key_id = db.Column(db.Integer, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime, nullable=True)
    
    __table_args__ = (
        db.Index('idx_onetime_prekeys_user_unused', 'user_id', 'is_used'),
        db.UniqueConstraint('user_id', 'key_id', name='_user_otk_id_uc'),
    )
