import requests
from app.crypto import decrypt_server

r = requests.post('http://127.0.0.1:8000/login', data={'username':'admin','password':'admin123'})
tk = r.json()['access_token']
h = {'Authorization': 'Bearer ' + tk}

print("--- Testing Phonetic Search (Rahool -> Rahul) ---")
r2 = requests.post('http://127.0.0.1:8000/secure-search?query=Rahool', headers=h)
d = r2.json()
print('Total matches:', d['count'])
names = [decrypt_server(res['customer_name']) for res in d['results']]
r_count = len([n for n in names if "Rahul" in n])
ro_count = len([n for n in names if "Rahool" in n])
print(f"Results contain {r_count} Rahuls and {ro_count} Rahools")

print("\n--- Testing Phonetic Search (Sarra -> Sarah) ---")
r3 = requests.post('http://127.0.0.1:8000/secure-search?query=Sarra', headers=h)
d3 = r3.json()
print('Total matches:', d3['count'])
names3 = [decrypt_server(res['customer_name']) for res in d3['results']]
s_count = len([n for n in names3 if "Sarah" in n])
sa_count = len([n for n in names3 if "Sarra" in n])
print(f"Results contain {s_count} Sarahs and {sa_count} Sarras")

print("\nALL PHONETIC TESTS COMPLETE")
