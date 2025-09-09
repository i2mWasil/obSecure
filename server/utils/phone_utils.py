# utils/phone_utils.py
import re

class PhoneUtils:
    @staticmethod
    def validate_phone_number(phone_number: str) -> bool:
        """Validate international phone number format"""
        # Basic E.164 format validation
        pattern = r'^\+[1-9]\d{1,14}$'
        return bool(re.match(pattern, phone_number))
    
    @staticmethod
    def normalize_phone_number(phone_number: str) -> str:
        """Normalize phone number to E.164 format"""
        # Remove all non-digit characters except +
        cleaned = re.sub(r'[^\d+]', '', phone_number)
        
        # Ensure it starts with +
        if not cleaned.startswith('+'):
            cleaned = '+' + cleaned
            
        return cleaned
