import hashlib
import json
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from app.database import SessionLocal, SecureData, SearchToken

# Key for demo (Same as frontend will use)
DEMO_KEY = hashlib.sha256(b"hackathon-secret-key").digest()[:16] # 128-bit AES

def encrypt(text: str) -> str:
    cipher = AES.new(DEMO_KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

def generate_tokens(text: str):
    text = text.lower().strip()
    tokens = []
    # Full word token
    tokens.append(hashlib.sha256(text.encode()).hexdigest())
    # Prefix tokens (e.g., "chennai" -> "che", "chen"...)
    if len(text) > 2:
        for i in range(3, len(text) + 1):
            prefix = text[:i]
            tokens.append(hashlib.sha256(prefix.encode()).hexdigest())
    return list(set(tokens))

def seed_data():
    names = ["Rahul", "Priya", "Amit", "Sneha", "Vikram", "Ananya", "Suresh", "Meera", "Arjun", "Kavita", 
             "John", "Sarah", "Michael", "Emma", "David", "Olivia", "James", "Sophia", "Robert", "Isabella"]
    cities = ["Chennai", "Bangalore", "Mumbai", "Delhi", "Hyderabad", "Pune", "Kolkata", "Ahmedabad", "Jaipur", "Lucknow",
              "New York", "London", "Tokyo", "Paris", "Berlin", "Sydney", "Singapore", "Dubai", "Toronto", "Mumbai"]

    db = SessionLocal()
    
    print("Clearing old data...")
    db.query(SearchToken).delete()
    db.query(SecureData).delete()
    db.commit()

    print("Generating 10,000 records...")
    
    records_to_add = []
    for i in range(10000):
        name = random.choice(names) + str(random.randint(1, 1000))
        city = random.choice(cities)
        
        # Simulating Client-Side logic
        enc_name = encrypt(name)
        enc_city = encrypt(city)
        
        # Search tokens for both name and city (prefixes)
        tokens = generate_tokens(name) + generate_tokens(city)
        
        record = SecureData(
            encrypted_name=enc_name,
            encrypted_city=enc_city
        )
        db.add(record)
        db.flush() # Get ID

        for t in tokens:
            token_entry = SearchToken(token=t, data_id=record.id)
            db.add(token_entry)
        
        if i % 1000 == 0:
            print(f"Inserted {i} records...")
            db.commit()

    db.commit()
    print("Successfully seeded 10,000 encrypted records!")
    db.close()

if __name__ == "__main__":
    seed_data()
