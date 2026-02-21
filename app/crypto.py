import hashlib
import hmac
import base64
import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# ENTERPRISE KEY MANAGEMENT SYSTEM (KMS)
# In PRD these would be in environment variables or HashiCorp Vault
KMS_KEYS = {
    "STORAGE_ENCRYPTION_KEY": b"a0f1f1574cdca14f8822063eff630361", # 32 bytes AES-256
    "SEARCH_TOKEN_KEY": b"78e670e84ac5a9d52b8662aa74dbec8d",      # 32 bytes HMAC
    "AUDIT_INTEGRITY_KEY": b"9d52b8662aa74dbec8db961d38f71c18"     # 32 bytes Blockchain
}

def encrypt(plaintext: str) -> str:
    """AES-256-CBC Encryption with Padding"""
    if plaintext is None: return None
    key = KMS_KEYS["STORAGE_ENCRYPTION_KEY"]
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_server(ciphertext_b64: str) -> str:
    """AES-256-CBC Decryption"""
    if not ciphertext_b64: return ""
    try:
        data = base64.b64decode(ciphertext_b64)
        iv = data[:16]
        ciphertext = data[16:]
        key = KMS_KEYS["STORAGE_ENCRYPTION_KEY"]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode('utf-8')
    except Exception:
        return "[PII_PROTECTED]"

def generate_search_token(text: str) -> str:
    """HMAC-SHA256 Blind Indexing"""
    if not text: return ""
    key = KMS_KEYS["SEARCH_TOKEN_KEY"]
    return hmac.new(key, text.lower().strip().encode(), hashlib.sha256).hexdigest()

def phonetic_encode(text: str) -> str:
    """Soundex Implementation for Phonetic Identity Matching"""
    if not text: return ""
    text = text.upper()
    mapping = {"BFPV": "1", "CGJKQSXZ": "2", "DT": "3", "L": "4", "MN": "5", "R": "6"}
    
    res = text[0]
    for char in text[1:]:
        for keys, val in mapping.items():
            if char in keys:
                if val != res[-1]:
                    res += val
                break
    res = (res + "000")[:4]
    return res

def generate_prefixes(text: str):
    """Multi-dimensional Search Token Generation"""
    if not text: return []
    clean = str(text).lower().strip()
    tokens = [generate_search_token(clean)] # Full exact match
    
    # Partial prefixes for names/large fields
    if len(clean) > 3:
        for i in range(3, min(len(clean), 15)):
            tokens.append(generate_search_token(clean[:i]))
            
    # Phonetic tokens for name variation handling
    words = clean.split()
    for word in words:
        if len(word) > 2:
            soundex = phonetic_encode(word)
            tokens.append(generate_search_token("PHONETIC_" + soundex))
            
    return list(set(tokens))

def calculate_block_hash(prev_hash, action, timestamp, user):
    payload = f"{prev_hash}{action}{timestamp}{user}"
    return hashlib.sha256(payload.encode()).hexdigest()
