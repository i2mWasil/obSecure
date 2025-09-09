-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_phone_hash ON users(phone_number_hash);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active, last_active);
CREATE INDEX IF NOT EXISTS idx_identity_keys_user_active ON identity_keys(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_signed_prekeys_user_active_expires ON signed_prekeys(user_id, is_active, expires_at);
CREATE INDEX IF NOT EXISTS idx_onetime_prekeys_user_unused ON onetime_prekeys(user_id, is_used);
CREATE INDEX IF NOT EXISTS idx_onetime_prekeys_created ON onetime_prekeys(created_at);

-- Create function to clean up old used OTKs
CREATE OR REPLACE FUNCTION cleanup_old_otks()
RETURNS void AS $$
BEGIN
    DELETE FROM onetime_prekeys 
    WHERE is_used = true 
    AND used_at < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;
