import random
import time
from app.database import SessionLocal, BankRecord, SearchToken, init_db
from app.crypto import encrypt, generate_prefixes, generate_search_token

def generate_enterprise_dataset():
    db = SessionLocal()
    init_db()
    
    # 🚨 CRITICAL: CLEAR PRODUCTION STATE FOR CLEAN SEED
    print("Zeroing database for enterprise seed...")
    db.query(SearchToken).delete()
    db.query(BankRecord).delete()
    db.commit()

    first_names = ["Arjun", "Deepak", "Rohan", "Siddharth", "Vikram", "Aditya", "Rahul", "Ananya", "Priya", "Sneha", 
                   "Ishani", "Meera", "Karan", "Sanjay", "Aman", "Rishi", "Varun", "Neha", "Kavya", "Tanvi"]
    last_names = ["Sharma", "Verma", "Gupta", "Malhotra", "Reddy", "Patel", "Singh", "Iyer", "Nair", "Das",
                  "Chopra", "Kapoor", "Joshi", "Kulkarni", "Deshmukh", "Choudhary", "Bose", "Menon", "Prasad"]
    
    cities = [("Mumbai", "MUM"), ("Delhi", "DEL"), ("Bangalore", "BLR"), ("Chennai", "MAA"), 
              ("Hyderabad", "HYD"), ("Pune", "PNQ"), ("Kolkata", "CCU"), ("Ahmedabad", "AMD")]
    
    ifsc_banks = ["HDFC", "ICIC", "SBIN", "UTIB", "KKBK"]

    existing_ids = set()
    existing_accs = set()
    
    print("Initializing engine: Generating 10,000 Unique Banking Profiles...")
    
    count = 0
    batch_size = 100
    
    while count < 10000:
        fn = random.choice(first_names)
        ln = random.choice(last_names)
        full_name = f"{fn} {ln} {random.randint(1000, 9999)}"
        
        cust_id = f"BNK-{random.randint(100000, 999999)}"
        acc_num = f"{random.randint(100000000000, 999999999999)}" # 12 Digit
        
        if cust_id in existing_ids or acc_num in existing_accs:
            continue
            
        existing_ids.add(cust_id)
        existing_accs.add(acc_num)
        
        city_name, city_code = random.choice(cities)
        bank_code = random.choice(ifsc_banks)
        ifsc = f"{bank_code}0{random.randint(100000, 999999)}"
        phone = f"+91 {random.randint(7000, 9999)}{random.randint(100000, 999999)}"
        kyc = f"KYC-{random.randint(10000, 99999)}-{random.randint(10000, 99999)}"
        
        # Generation Logic
        rec = BankRecord(
            customer_id=encrypt(cust_id),
            full_name=encrypt(full_name),
            account_number=encrypt(acc_num),
            phone_number=encrypt(phone),
            ifsc_code=encrypt(ifsc),
            branch=encrypt(f"{city_name} {random.choice(['Main', 'West', 'East', 'IT Park'])}"),
            city=encrypt(city_name),
            balance=encrypt(f"{random.randint(1000, 5000000)}"),
            risk_score=encrypt(random.choice(["Low", "Medium", "High", "Critical"])),
            kyc_id=encrypt(kyc),
            device_id=encrypt(hashlib.sha1(str(random.random()).encode()).hexdigest()[:16].upper()),
            last_transaction_amount=encrypt(str(random.randint(10, 50000))),
            last_login_location=encrypt(f"{random.choice(cities)[0]}, India")
        )
        db.add(rec)
        db.flush() 

        # MULTI-FIELD SEARCH TOKENIZATION
        field_tokens = []
        field_tokens += [(t, "name") for t in generate_prefixes(full_name)]
        field_tokens += [(t, "phone") for t in generate_prefixes(phone)]
        field_tokens += [(t, "account") for t in generate_prefixes(acc_num)]
        field_tokens += [(t, "ifsc") for t in generate_prefixes(ifsc)]
        field_tokens += [(t, "city") for t in generate_prefixes(city_name)]
        field_tokens += [(t, "kyc") for t in generate_prefixes(kyc)]

        for token, field in field_tokens:
            db.add(SearchToken(token=token, field=field, record_id=rec.id))
        
        count += 1
        if count % batch_size == 0:
            db.commit()
            print(f"Propagating: {count} / 10,000 secure records indexed...")

    db.commit()
    print(f"SUCCESS: Secure Enterprise DB seeded with {count} unique identities.")
    db.close()

import hashlib
if __name__ == "__main__":
    generate_enterprise_dataset()
