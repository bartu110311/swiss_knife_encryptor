import hashlib
import json
import secrets

# RFC 3526 2048-bit MODP Group Sabitleri
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16
)
Q = (P - 1) // 2
G = 2

def generate_keypair(priv_path, pub_path):
    x = secrets.randbelow(Q - 1) + 1
    y = pow(G, x, P)
    
    with open(priv_path, "w", encoding="utf-8") as f:
        json.dump({"x": x}, f, indent=4)
    with open(pub_path, "w", encoding="utf-8") as f:
        json.dump({"y": y}, f, indent=4)
        
    print(f"[+] A pair of Schnorr ZKP keys is created: {pub_path}, {priv_path}")

def generate_proof(priv_key_path, message=""):
    with open(priv_key_path, "r", encoding="utf-8") as f:
        x = json.load(f)["x"]
        
    r = secrets.randbelow(Q - 1) + 1
    t = pow(G, r, P)
    y = pow(G, x, P)
    
    h_input = f"{G}:{y}:{t}:{message}".encode("utf-8")
    c = int(hashlib.sha256(h_input).hexdigest(), 16) % Q
    s = (r + c * x) % Q
    
    proof = {"t": t, "s": s, "message": message}
    return json.dumps(proof)

def verify_proof(pub_key_path, proof_json):
    with open(pub_key_path, "r", encoding="utf-8") as f:
        y = json.load(f)["y"]
        
    proof = json.loads(proof_json)
    t = proof["t"]
    s = proof["s"]
    message = proof.get("message", "")
    
    h_input = f"{G}:{y}:{t}:{message}".encode("utf-8")
    c = int(hashlib.sha256(h_input).hexdigest(), 16) % Q
    
    lhs = pow(G, s, P)
    rhs = (t * pow(y, c, P)) % P
    
    return lhs == rhs