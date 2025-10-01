from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend

def generate_keys():
    """Generates a private and public key pair."""
    # Generate a private key using the recommended elliptic curve
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Get the public key from the private key
    public_key = private_key.public_key()

    # Save the private key to a file
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))

    # Save the public key to a file
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ))

    print("Keys generated successfully:")
    print(" - private_key.pem (KEEP THIS SAFE AND PRIVATE!)")
    print(" - public_key.pem (You will embed this in your script)")

if __name__ == "__main__":
    generate_keys()