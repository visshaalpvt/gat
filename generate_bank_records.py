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
             "Rahul Sharma", "Priya Patel", "Amit Kumar", "Sneha Gupta", "Vikram Singh", "Ananya Reddy"]
    
    cities = ["New York", "London", "Chennai", "Mumbai", "Dubai", "Singapore", "Toronto", "Sydney", 
              "Paris", "Tokyo", "Berlin", "Bangalore", "Delhi", "Hyderabad"]
    
    banks = ["Global Bank Corp", "Swift Reserve", "Vertex Trust", "Apex Financials", "Zenith Banking"]
    
    print("Generating 10,000 secure bank records...")
    
    batch_size = 500
    for i in range(20): # 20 * 500 = 10,000
        records = []
        for j in range(batch_size):
            name = f"{random.choice(names)} {random.randint(100, 999)}"
            city = random.choice(cities)
            acc = f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"
            cust_id = f"CUST-{random.randint(100000, 999999)}"
            
            # Encrypt
            rec = BankRecord(
                customer_id=encrypt(cust_id),
                customer_name=encrypt(name),
                account_number=encrypt(acc),
                bank_name=encrypt(random.choice(banks)),
                branch=encrypt(f"{city} Central"),
                city=encrypt(city),
                balance=encrypt(str(random.randint(5000, 1000000)))
            )
            db.add(rec)
            db.flush()
            
            # Tokens
            t_list = generate_prefixes(name) + generate_prefixes(acc) + generate_prefixes(city)
            for t in set(t_list):
                db.add(SearchToken(token=t, record_id=rec.id))
        
        db.commit()
        print(f"Batch {i+1}/20 completed...")

    print("Success: 10,000 records encrypted and indexed.")
    db.close()

if __name__ == "__main__":
    generate_10k_records()
