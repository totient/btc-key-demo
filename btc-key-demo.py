import hashlib
import ecdsa
import random
import time
import binascii

def generate_random_private_key():
    """Generate a random 256-bit private key"""
    return random.randint(1, ecdsa.SECP256k1.order - 1)

def private_key_to_public_key(private_key):
    """Convert private key to uncompressed public key"""
    signing_key = ecdsa.SigningKey.from_secret_exponent(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    return b'\x04' + verifying_key.to_string()

def public_key_matches(generated_pub_key, target_pub_key):
    """Compare two public keys"""
    return generated_pub_key == target_pub_key

def hex_to_bytes(hex_string):
    """Convert hex string to bytes, handling optional '0x' prefix"""
    hex_string = hex_string.lower().strip()
    if hex_string.startswith('0x'):
        hex_string = hex_string[2:]
    return binascii.unhexlify(hex_string)

def attempt_brute_force(target_pubkey_hex, max_attempts=1000):
    """
    Demonstration of attempting to brute force a private key from a P2PK public key
    WARNING: This is for educational purposes only
    
    Args:
        target_pubkey_hex (str): The target public key in hex format
        max_attempts (int): Maximum number of attempts to try
    """
    try:
        # Convert the target public key from hex to bytes
        target_pubkey = hex_to_bytes(target_pubkey_hex)
        
        print(f"Target public key: {target_pubkey_hex}")
        print("Beginning demonstration of brute force attempt...")
        print("Note: In reality, the probability of finding a match is astronomically small")
        
        attempts = 0
        start_time = time.time()
        
        while attempts < max_attempts:
            private_key = generate_random_private_key()
            public_key = private_key_to_public_key(private_key)
            
            attempts += 1
            if attempts % 100 == 0:
                elapsed = time.time() - start_time
                print(f"Attempted {attempts} keys in {elapsed:.2f} seconds")
            
            if public_key_matches(public_key, target_pubkey):
                print("\nMatch found! (This would be extremely unlikely in practice)")
                print(f"Private Key (hex): {hex(private_key)}")
                return private_key
        
        print("\nNo match found (this is the expected outcome)")
        print(f"Attempted {attempts} keys in {time.time() - start_time:.2f} seconds")
        print("\nThis demonstration shows why brute forcing Bitcoin private keys is infeasible:")
        print("- The key space is the size of the SECP256k1 curve order (~2^256)")
        print("- Even with billions of attempts per second, the probability of success is effectively zero")
        print("- The universe would likely end before a match would be found")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        print("Please ensure the public key is in the correct format (hex string)")
    
    return None

if __name__ == "__main__":
    # Example usage with Satoshi's first public key
    example_pubkey = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"
    attempt_brute_force(example_pubkey, max_attempts=1000)
