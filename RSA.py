import random
import math

#Group: Nate Hazeslip, Kaden Hyde, and Seth Wojcik

def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n<=1:
        return False
    if n<=3:
        return True
    if n%2==0:
        return False
    
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    
    for _ in range(k):
        a = random.randint(2, n-2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
        
    return True

def generate_large_prime(bits = 1024):
    """Generate a large prime number of specified bit length."""

    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Ensure it's odd and has the correct bit length

        if is_prime(num):
            return num
        
def gcd(a, b):
    """Compute the greatest common divisor using Euclid's algorithm."""

    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find the modular inverse."""
    
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y

def mod_inverse(a, m):
    """Find the modular inverse of a modulo m using extended Euclidean Algorithm."""

    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m

def generate_rsa_keys(bits=1024):
    """Generate RSA public and private keys."""
    
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    
    while p == q:
        q = generate_large_prime(bits // 2)

    n = p * q

    phi_n = (p - 1) * (q - 1)
    
    e = 65537  # Common choice for e
    while gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)
    
    d = mod_inverse(e, phi_n)

    public_key = (n, e)
    private_key = (n, d)
    
    return public_key, private_key

def text_to_ascii_blocks(text, block_size):
    # Convert text to ASCII blocks of specified size
    text = text.upper()
    ascii_table_values = [ord(char) for char in text]

    blocks = []

    for i in range(0, len(ascii_table_values), block_size):
        block_values = ascii_table_values[i:i + block_size]

        block_number = 0
        for value in block_values:
            block_number = (block_number << 8) + value
        blocks.append(block_number)

    return blocks

def text_to_ascii_number(text):
    """Convert text to a single ASCII number."""
    text = text.upper()
    ascii_number = 0
    for char in text:
        ascii_number = (ascii_number << 8) + ord(char)
    return ascii_number

def ascii_number_to_text(number, length):
    """Convert ASCII number back to text."""
    text_chars = []
    temp = number
    for _ in range(length):
        ascii_val = temp & 255
        text_chars.insert(0, chr(ascii_val))
        temp >>= 8
    return ''.join(text_chars)

def rsa_encrypt_message(message, public_key):
    """Encrypt a message using RSA public key."""
    n, e = public_key
    ascii_num = text_to_ascii_number(message)
    
    # Check if message is too long for the key
    max_message_size = n.bit_length() // 8
    if len(message) > max_message_size:
        raise ValueError(f"Message too long. Max {max_message_size} characters for this key.")
    
    encrypted = pow(ascii_num, e, n)
    return encrypted

def rsa_decrypt_message(encrypted_message, private_key):
    """Decrypt a message using RSA private key."""
    n, d = private_key
    decrypted_num = pow(encrypted_message, d, n)
    
    # Estimate original length (each character = 8 bits)
    original_length = (decrypted_num.bit_length() + 7) // 8
    decrypted_text = ascii_number_to_text(decrypted_num, original_length)
    return decrypted_text

def rsa_sign_message(message, private_key):
    """Create a digital signature using private key."""
    n, d = private_key
    ascii_num = text_to_ascii_number(message)
    
    # Check if message is too long for signing
    max_message_size = n.bit_length() // 8
    if len(message) > max_message_size:
        raise ValueError(f"Message too long for signing. Max {max_message_size} characters.")
    
    signature = pow(ascii_num, d, n)
    return signature

def rsa_verify_signature(signature, public_key, original_message):
    """Verify a digital signature using public key."""
    n, e = public_key
    decrypted_num = pow(signature, e, n)
    
    # Reconstruct the signed message
    original_length = (decrypted_num.bit_length() + 7) // 8
    decrypted_message = ascii_number_to_text(decrypted_num, original_length)
    
    # Compare with original message
    return decrypted_message == original_message.upper()

def ascii_blocks_to_text(blocks, original_length):
    #Convert ASCII blocks back to text
    text_chars = []
    for block in blocks:
        temp_block = block
        block_values = []

        while temp_block > 0:
            ascii_value = temp_block & 255
            block_values.insert(0, ascii_value)
            temp_block >>= 8
        
        text_chars.extend([chr(value) for value in block_values])

    return ''.join(text_chars)[:original_length]

def calculate_block_size(n):
    #Calculate block size for ascii values that is optimal

    return n.bit_length() // 8 - 1

def rsa_encrypt_block(block, public_key):
    #Encrypt a single block using the public key
    n, e = public_key
    return pow(block, e, n)

def rsa_decrypt_block(block, private_key):
    #Decrypt a single block using the private key
    n, d = private_key
    return pow(block, d, n)

def encrypt_text_ascii(text, public_key):
    #Encrypt text using RSA and ASCII block conversion
    n, e = public_key
    block_size = calculate_block_size(n)
    ascii_blocks = text_to_ascii_blocks(text, block_size)

    encrypted_blocks = []
    for block in ascii_blocks:
        encrypted_block = rsa_encrypt_block(block, public_key)
        encrypted_blocks.append(encrypted_block)

    return encrypted_blocks, len(text), block_size

def decrypt_text_ascii(encrypted_blocks, private_key, original_length, block_size):
    #Decrypt encrypted ASCII blocks back to text
    decrypted_blocks = []
    for block in encrypted_blocks:
        decrypted_block = rsa_decrypt_block(block, private_key)
        decrypted_blocks.append(decrypted_block)

    return ascii_blocks_to_text(decrypted_blocks, original_length)

def generate_digital_signature(private_key, message, n):
    signature = (message**private_key) % n
    return signature

def verify_digital_signature(signature, public_key, n, message):
    if ((signature**public_key) % n == message):
        valid = True
    else:
        valid = False
    return valid

def show_encryption_process(text, public_key):
    #Shows the encryption process step by step with ascii values
    print("\n" + "=" * 200)
    print("Encryption Process:")
    print("=" * 200)

    print(f"Original Text: {text}")
    upper_text = text.upper()
    print(f"Uppercase Text: {upper_text}")

    ascii_values = [ord(char) for char in upper_text]
    print(f"ASCII Values: {ascii_values}")

    n, e = public_key
    block_size = calculate_block_size(n)
    print(f"Calculated Block Size: {block_size}")

    blocks = text_to_ascii_blocks(text, block_size)
    print(f"Numerical Blocks: {blocks}")

    encrypted_blocks = [rsa_encrypt_block(block, public_key) for block in blocks]
    print(f"\nEncrypted blocks: {encrypted_blocks}")

    return encrypted_blocks, len(text), block_size


def main():
    """Main function with the exact user interface from the sample."""
    global encrypted_messages, digital_signatures, public_key, private_key
    
    # Initialize storage
    encrypted_messages = []
    digital_signatures = []
    
    # Generate initial keys
    print("RSA keys have been generated.")
    public_key, private_key = generate_rsa_keys(1024)
    
    while True:
        print("\nPlease select your user type:")
        print("1. A public user")
        print("2. The owner of the keys")
        print("3. Exit program")
        
        try:
            user_choice = int(input("Enter your choice: "))
        except ValueError:
            print("Please enter a valid number (1-3).")
            continue
        
        if user_choice == 1:  # Public user
            public_user_menu()
        elif user_choice == 2:  # Owner
            owner_menu()
        elif user_choice == 3:  # Exit
            print("Bye for now!")
            break
        else:
            print("Invalid choice. Please enter 1-3.")

def public_user_menu():
    """Menu for public users (encrypt messages, verify signatures)."""
    global encrypted_messages, digital_signatures, public_key
    
    while True:
        print("\nAs a public user, what would you like to do?")
        print("1. Send an encrypted message")
        print("2. Authenticate a digital signature")
        print("3. Exit")
        
        try:
            choice = int(input("Enter your choice: "))
        except ValueError:
            print("Please enter a valid number (1-3).")
            continue
        
        if choice == 1:  # Send encrypted message
            message = input("Enter a message: ")
            if not message:
                print("Message cannot be empty!")
                continue
            
            try:
                encrypted = rsa_encrypt_message(message, public_key)
                encrypted_messages.append((encrypted, len(message)))
                print("Message encrypted and sent.")
                print(f"Encrypted message: {encrypted}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif choice == 2:  # Authenticate signature
            if not digital_signatures:
                print("There are no signatures to authenticate.")
                continue
            
            print("The following messages are available:")
            for i, (sig, msg, _) in enumerate(digital_signatures, 1):
                print(f"{i}. {msg}")
            
            try:
                sig_choice = int(input("Enter your choice: "))
                if 1 <= sig_choice <= len(digital_signatures):
                    signature, original_message, _ = digital_signatures[sig_choice - 1]
                    is_valid = rsa_verify_signature(signature, public_key, original_message)
                    if is_valid:
                        print("Signature is valid.")
                        print(f"Signature value: {signature}")
                    else:
                        print("Signature is NOT valid.")
                else:
                    print("Invalid choice.")
            except ValueError:
                print("Please enter a valid number.")
                
        elif choice == 3:  # Exit public menu
            break
        else:
            print("Invalid choice. Please enter 1-3.")

def owner_menu():
    """Menu for key owner (encrypt, decrypt, sign messages, manage keys)."""
    global encrypted_messages, digital_signatures, public_key, private_key
    
    while True:
        print("\nAs the owner of the keys, what would you like to do?")
        print("1. Encrypt a message")
        print("2. Decrypt a received message")
        print("3. Digitally sign a message")
        print("4. Show the keys")
        print("5. Generate a new set of keys")
        print("6. Exit")
        
        try:
            choice = int(input("Enter your choice: "))
        except ValueError:
            print("Please enter a valid number (1-6).")
            continue
        
        if choice == 1:  # Encrypt message (NEW OPTION)
            message = input("Enter a message to encrypt: ")
            if not message:
                print("Message cannot be empty!")
                continue
            
            try:
                encrypted = rsa_encrypt_message(message, public_key)
                encrypted_messages.append((encrypted, len(message)))
                print("Message encrypted.")
                print(f"Encrypted message: {encrypted}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif choice == 2:  # Decrypt message
            if not encrypted_messages:
                print("No messages available to decrypt.")
                continue
            
            print("The following messages are available:")
            for i, (encrypted, length) in enumerate(encrypted_messages, 1):
                print(f"{i}. (length = {length}) - Encrypted: {encrypted}")
            
            try:
                msg_choice = int(input("Enter your choice: "))
                if 1 <= msg_choice <= len(encrypted_messages):
                    encrypted_message, length = encrypted_messages[msg_choice - 1]
                    decrypted = rsa_decrypt_message(encrypted_message, private_key)
                    print(f"Decrypted message: {decrypted}")
                    # Remove the decrypted message
                    encrypted_messages.pop(msg_choice - 1)
                else:
                    print("Invalid choice.")
            except ValueError:
                print("Please enter a valid number.")
            except Exception as e:
                print(f"Decryption failed: {e}")
                
        elif choice == 3:  # Sign message
            message = input("Enter a message to sign: ")
            if not message:
                print("Message cannot be empty!")
                continue
            
            try:
                signature = rsa_sign_message(message, private_key)
                digital_signatures.append((signature, message, len(message)))
                print("Message signed.")
                print(f"Digital signature: {signature}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif choice == 4:  # Show keys
            n, e = public_key
            n_priv, d = private_key
            print(f"Public Key (n): {n}")
            print(f"Public Key (e): {e}")
            print(f"Private Key (d): {d}")
            print(f"Modulus bit length: {n.bit_length()} bits")
            print(f"Max message length: {n.bit_length() // 8} characters")
            
        elif choice == 5:  # Generate new keys
            print("Generating a new set of keys...")
            public_key, private_key = generate_rsa_keys(1024)
            # Clear existing messages and signatures when keys change
            encrypted_messages.clear()
            digital_signatures.clear()
            print("New keys generated successfully!")
            
        elif choice == 6:  # Exit owner menu
            break
        else:
            print("Invalid choice. Please enter 1-6.")

encrypted_messages = []
digital_signatures = []
public_key = None
private_key = None

if __name__ == "__main__":
    main()
