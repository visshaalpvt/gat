import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

# ===== FIXED KEYS (Simple & Matching JS Exactly) =====
# These are derived deterministically so both Python and JS produce identical output.
MASTER_SECRET = "enterprise-bank-master-key-2026"
AES_KEY = hashlib.sha256(b"aes-key-enterprise-2026").digest()  # 32 bytes for AES-256
HMAC_KEY = hashlib.sha256(b"hmac-key-enterprise-2026").digest()  # 32 bytes for HMAC


def encrypt(plaintext: str) -> str:
    """AES-256-CBC Encryption with IV prepended"""
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    # PKCS7 padding
    padding_len = 16 - (len(plaintext.encode('utf-8')) % 16)
    padded = plaintext.encode('utf-8') + bytes([padding_len] * padding_len)
    ciphertext = cipher.encrypt(padded)
    # Return: base64(iv + ciphertext)
    return base64.b64encode(iv + ciphertext).decode('utf-8')


def decrypt_server(ciphertext_b64: str) -> str:
    """Server-side decryption (for verification only)"""
    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ct)
    pad_len = padded[-1]
    return padded[:-pad_len].decode('utf-8')


def phonetic_encode(name: str) -> str:
    """Manual Soundex implementation for phonetic matching"""
    if not name: return "Z000"
    name = name.upper()
    first = name[0]
    mapping = {
        'BFPV': '1', 'CGJKQSXZ': '2', 'DT': '3',
        'L': '4', 'MN': '5', 'R': '6'
    }
    
    codes = ""
    for char in name[1:]:
        for k, v in mapping.items():
            if char in k:
                if not codes or codes[-1] != v:
                    codes += v
                break
    
    clean = (codes.replace("0", ""))[:3]
    return (first + clean).ljust(4, "0")

def generate_search_token(text: str) -> str:
    """HMAC-SHA256 token for blind index search"""
    h = HMAC.new(HMAC_KEY, digestmod=SHA256)
    h.update(text.lower().strip().encode('utf-8'))
    return h.hexdigest()

def generate_prefixes(text: str):
    """Generate search tokens for the full word, prefixes, and phonetic variants"""
    words = text.lower().strip().split()
    all_tokens = []
    
    for word in words:
        if len(word) < 2: continue
        # 1. Exact/Prefix Tokens
        all_tokens.append(generate_search_token(word))
        for i in range(3, len(word)):
            all_tokens.append(generate_search_token(word[:i]))
        
        # 2. Phonetic token (THE WINNING FEATURE)
        soundex = phonetic_encode(word)
        all_tokens.append(generate_search_token("FUZZY_" + soundex))
        
    return list(set(all_tokens))


def mask_data(text: str, visible_chars: int = 4) -> str:
    if len(text) <= visible_chars:
        return "****"
    return "*" * (len(text) - visible_chars) + text[-visible_chars:]


def calculate_block_hash(prev_hash, action, timestamp, user):
    content = f"{prev_hash}|{action}|{timestamp}|{user}"
    return hashlib.sha256(content.encode()).hexdigest()
