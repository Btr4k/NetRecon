import base64
import hashlib
import os
import string
import random
import platform
import uuid

class APIKeyProtector:
    def __init__(self):
        # Multiple layers of encryption and more complex salts
        self._secured_key1 = "Ty751bhZHPmi+kPnPkz0YzID0pdV33o="  # Will update with new encryption
        self._secured_key2 = "T0iGpJcQatqX0UP9Qy6OMBlL8Z872QIz0CrgR/z6htE="  # Will update with new encryption
        
        # Make salts dynamic and hardware-dependent
        self._salt_layers = self._generate_salt_layers()
        
    def _generate_salt_layers(self):
        """Generate multiple salt layers based on hardware and system info"""
        try:
            # Hardware-specific information
            machine_id = str(uuid.getnode())  # MAC address
            cpu_info = platform.processor()
            system_info = platform.system() + platform.release()
            
            # Create multiple salt layers
            salt1 = hashlib.sha256(machine_id.encode()).digest()
            salt2 = hashlib.sha512(cpu_info.encode()).digest()
            salt3 = hashlib.blake2b(system_info.encode()).digest()
            
            return [salt1, salt2, salt3]
        except:
            return [b"fallback"] * 3

    def _get_machine_fingerprint(self):
        """Generate a complex machine fingerprint"""
        components = [
            platform.node(),
            platform.architecture()[0],
            platform.machine(),
            platform.processor(),
            str(uuid.getnode()),
            os.path.expanduser('~')
        ]
        return hashlib.sha512(''.join(components).encode()).digest()

    def _multi_layer_encrypt(self, data, salt_layers):
        """Multi-layer encryption"""
        try:
            current_data = data.encode()
            
            # Apply multiple encryption layers in reverse
            for salt in reversed(salt_layers):
                key = hashlib.pbkdf2_hmac(
                    'sha256',
                    self._get_machine_fingerprint(),
                    salt,
                    100000
                )
                
                # XOR encryption
                temp = []
                for i in range(len(current_data)):
                    temp.append(current_data[i] ^ key[i % len(key)])
                current_data = bytes(temp)
            
            return base64.b64encode(current_data).decode()
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return None

    def _multi_layer_decrypt(self, encrypted_data, salt_layers):
        """Multi-layer decryption"""
        try:
            data = base64.b64decode(encrypted_data)
            
            # Apply multiple decryption layers
            for salt in salt_layers:
                key = hashlib.pbkdf2_hmac(
                    'sha256',
                    self._get_machine_fingerprint(),
                    salt,
                    100000
                )
                
                # XOR decryption
                temp = []
                for i in range(len(data)):
                    temp.append(data[i] ^ key[i % len(key)])
                data = bytes(temp)
            
            return data.decode()
        except:
            return None

    def get_api_keys(self):
        """Get API keys with multi-layer decryption"""
        try:
            key1 = self._multi_layer_decrypt(self._secured_key1, self._salt_layers)
            key2 = self._multi_layer_decrypt(self._secured_key2, self._salt_layers)
            return key1, key2
        except:
            return None, None

def generate_encrypted_keys(key1, key2):
    """Generate encrypted keys with the new multi-layer system"""
    protector = APIKeyProtector()
    
    # Encrypt both keys
    enc1 = protector._multi_layer_encrypt(key1, protector._salt_layers)
    enc2 = protector._multi_layer_encrypt(key2, protector._salt_layers)
    
    print("\nEncrypted API Keys (update these in the APIKeyProtector class):")
    print(f"self._secured_key1 = \"{enc1}\"")
    print(f"self._secured_key2 = \"{enc2}\"")

if __name__ == "__main__":
    print("API Key Encryption Tool")
    print("-" * 50)
    api_key1 = input("Enter API Key 1 (C99.nl): ")
    api_key2 = input("Enter API Key 2 (HIBP): ")
    generate_encrypted_keys(api_key1, api_key2)