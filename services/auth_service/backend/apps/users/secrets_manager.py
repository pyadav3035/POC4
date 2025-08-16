"""
Secure secrets management for microservice deployment.
"""

import os
import json
import logging
from django.conf import settings
from django.core.cache import cache
from cryptography.fernet import Fernet
import base64

logger = logging.getLogger(__name__)


class SecretsManager:
    """
    Secure secrets management with encryption and caching.
    """
    
    def __init__(self):
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.cache_prefix = "secrets"
        self.cache_timeout = 300  # 5 minutes
    
    def _get_or_create_encryption_key(self):
        """
        Get or create encryption key for secrets.
        """
        key_env = os.environ.get('SECRETS_ENCRYPTION_KEY')
        if key_env:
            return key_env.encode()
        
        # Generate new key (in production, this should be managed externally)
        key = Fernet.generate_key()
        logger.warning("Generated new encryption key - store this securely in production!")
        return key
    
    def encrypt_secret(self, secret_value):
        """
        Encrypt a secret value.
        """
        if isinstance(secret_value, str):
            secret_value = secret_value.encode()
        
        encrypted = self.cipher_suite.encrypt(secret_value)
        return base64.b64encode(encrypted).decode()
    
    def decrypt_secret(self, encrypted_value):
        """
        Decrypt a secret value.
        """
        try:
            encrypted_bytes = base64.b64decode(encrypted_value.encode())
            decrypted = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt secret: {str(e)}")
            raise SecretDecryptionError("Failed to decrypt secret")
    
    def store_secret(self, key, value, encrypt=True):
        """
        Store a secret with optional encryption.
        """
        try:
            if encrypt:
                stored_value = {
                    'encrypted': True,
                    'value': self.encrypt_secret(value)
                }
            else:
                stored_value = {
                    'encrypted': False,
                    'value': value
                }
            
            cache_key = f"{self.cache_prefix}:{key}"
            cache.set(cache_key, json.dumps(stored_value), timeout=self.cache_timeout)
            
            logger.info(f"Secret stored: {key} (encrypted: {encrypt})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store secret {key}: {str(e)}")
            return False
    
    def get_secret(self, key, default=None):
        """
        Retrieve a secret value.
        """
        try:
            cache_key = f"{self.cache_prefix}:{key}"
            cached_data = cache.get(cache_key)
            
            if cached_data:
                secret_data = json.loads(cached_data)
                
                if secret_data['encrypted']:
                    return self.decrypt_secret(secret_data['value'])
                else:
                    return secret_data['value']
            
            # Fallback to environment variable
            env_value = os.environ.get(key.upper())
            if env_value:
                # Cache the environment value
                self.store_secret(key, env_value, encrypt=True)
                return env_value
            
            return default
            
        except Exception as e:
            logger.error(f"Failed to retrieve secret {key}: {str(e)}")
            return default
    
    def delete_secret(self, key):
        """
        Delete a secret.
        """
        try:
            cache_key = f"{self.cache_prefix}:{key}"
            cache.delete(cache_key)
            logger.info(f"Secret deleted: {key}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret {key}: {str(e)}")
            return False
    
    def rotate_encryption_key(self):
        """
        Rotate the encryption key (requires re-encrypting all secrets).
        """
        logger.warning("Encryption key rotation not implemented - requires external key management")
        # In production, this would integrate with AWS KMS, HashiCorp Vault, etc.
        pass


class SecretDecryptionError(Exception):
    """Exception raised when secret decryption fails."""
    pass


# Global secrets manager instance
secrets_manager = SecretsManager()


def get_database_credentials():
    """
    Get database credentials securely.
    """
    return {
        'name': secrets_manager.get_secret('database_name', settings.DATABASES['default']['NAME']),
        'user': secrets_manager.get_secret('database_user', settings.DATABASES['default']['USER']),
        'password': secrets_manager.get_secret('database_password', settings.DATABASES['default']['PASSWORD']),
        'host': secrets_manager.get_secret('database_host', settings.DATABASES['default']['HOST']),
        'port': secrets_manager.get_secret('database_port', settings.DATABASES['default']['PORT'])
    }


def get_jwt_secret():
    """
    Get JWT signing secret securely.
    """
    return secrets_manager.get_secret('jwt_secret_key', settings.SECRET_KEY)


def store_api_key(service_name, api_key):
    """
    Store API key for external service.
    """
    key = f"api_key_{service_name}"
    return secrets_manager.store_secret(key, api_key, encrypt=True)


def get_api_key(service_name):
    """
    Get API key for external service.
    """
    key = f"api_key_{service_name}"
    return secrets_manager.get_secret(key)