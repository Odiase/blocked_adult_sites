from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Load your existing private key
with open("private_key.pem", "rb") as key_file:
    private_key = load_pem_private_key(key_file.read(), password=None)

# Extract the matching public key
public_key = private_key.public_key()

# Serialize it to PEM format (so you can copy into your app)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save to file (optional)
with open("public_key.pem", "wb") as f:
    f.write(public_pem)

print("✅ Public key regenerated successfully!")
print(public_pem.decode())
