import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

def sign_blocklist():
    """Signs the blocklist.txt file using the private key."""
    try:
        # Load your private key from the local file
        with open("private_key.pem", "rb") as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Load the content of your updated blocklist file
        with open("blocklist.txt", "rb") as f:
            blocklist_content = f.read()

        # Create a digital signature for the new content
        signature = private_key.sign(
            blocklist_content,
            ec.ECDSA(hashes.SHA256())
        )

        # Save the signature to a new file
        with open("blocklist.sig", "wb") as f:
            f.write(signature)

        print("New blocklist.sig file created successfully.")

    except FileNotFoundError as e:
        print(f"Error: Required file not found. Make sure 'private_key.pem' and 'blocklist.txt' are in the same directory.")
    except Exception as e:
        print(f"An error occurred while signing the blocklist: {e}")

if __name__ == "__main__":
    sign_blocklist()