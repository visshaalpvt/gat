import random
from app.database import SessionLocal, BankRecord, SearchToken, init_db
from app.crypto import encrypt, generate_prefixes

def generate_10k_records():
    db = SessionLocal()
    init_db()
    
    # Clear existing
    db.query(SearchToken).delete()
    db.query(BankRecord).delete()
    db.commit()

    names = ["John Smith", "Sarah Miller", "Michael Chen", "Emma Watson", "David Brown", "Olivia Garcia", 
             "James Wilson", "Sophia Martinez", "Robert Taylor", "Isabella Anderson", "William Lee", 
             "Mia Hernandez", "Joseph Moore", "Charlotte Young", "Thomas White", "Amelia King",
             "Rahul Sharma", "Rahool Sharma", "Ragul Sharma", "Sarra Miller", "Maikel Chen",
             "Priya Patel", "Amit Kumar", "Sneha Gupta", "Vikram Singh", "Ananya Reddy"]
    
    cities = ["New York", "London", "Chennai", "Mumbai", "Dubai", "Singapore", "Toronto", "Sydney", 
              "Paris", "Tokyo", "Berlin", "Bangalore", "Delhi", "Hyderabad"]
    
    banks = ["Global Bank Corp", "Swift Reserve", "Vertex Trust", "Apex Financials", "Zenith Banking"]
    
    print("Generating 10,000 secure enterprise bank records (Committing every 100)...")
    
    batch_size = 100
    for i in range(100): # 100 * 100 = 10,000
        for j in range(batch_size):
            raw_name = random.choice(names)
            name = f"{raw_name} {random.randint(100, 9999)}"
            city = random.choice(cities)
            acc = f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"
            cust_id = f"CUST-{random.randint(100000, 999999)}"
            
            # Additional Enterprise Data
            phone = f"+91 {random.randint(7000, 9999)}{random.randint(100000, 999999)}"
            pan = f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=5))}{random.randint(1000, 9999)}{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}"
            aadhaar = f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"
            email = f"{raw_name.lower().replace(' ', '')}{random.randint(10,999)}@banksecure.com"
            risk = random.choice(["Low", "Medium", "High", "Critical"])
            kyc = random.choice(["VERIFIED", "PENDING", "REJECTED"])

            # Encrypt
            rec = BankRecord(
                customer_id=encrypt(cust_id),
                customer_name=encrypt(name),
                account_number=encrypt(acc),
                bank_name=encrypt(random.choice(banks)),
                branch=encrypt(f"{city} Central"),
                city=encrypt(city),
                balance=encrypt(str(random.randint(5000, 1000000))),
                pan=encrypt(pan),
                aadhaar=encrypt(aadhaar),
                phone=encrypt(phone),
                email=encrypt(email),
                risk_score_enc=encrypt(risk),
                kyc_status_enc=encrypt(kyc)
            )
            db.add(rec)
            db.flush()
            
            # Multi-Field Blind Indexing
            t_list = generate_prefixes(name) + \
                     generate_prefixes(city) + \
                     generate_prefixes(phone) + \
                     generate_prefixes(pan) + \
                     generate_prefixes(aadhaar) + \
                     generate_prefixes(acc)

            for t in set(t_list):
                db.add(SearchToken(token=t, record_id=rec.id))
        
        db.commit()
        if (i+1) % 5 == 0:
            print(f"Progress: {(i+1) * batch_size} / 10,000 records completed...")

    print("Success: 10,000 enterprise records encrypted and indexed.")
    db.close()

if __name__ == "__main__":
    generate_10k_records()
