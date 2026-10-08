from crypto_utils import SecureSession


print("Creating Akshatha's secure session...")
akshatha = SecureSession()

print("Creating Rahul's secure session...")
rahul = SecureSession()


# Exchange public keys
akshatha_public = akshatha.get_public_key()
rahul_public = rahul.get_public_key()


print("\nPublic keys exchanged.")


# Generate session keys
akshatha.generate_session_key(
    rahul_public
)

rahul.generate_session_key(
    akshatha_public
)


print("Session keys generated.")


# Check whether both keys are identical
if akshatha.session_key == rahul.session_key:

    print("\n✅ X25519 + HKDF SUCCESS")
    print("Both users have the same session key.")

else:

    print("\n❌ ERROR")
    print("Session keys do not match.")


# ==========================================
# TEST ENCRYPTION
# ==========================================

original_message = "Hello Rahul! This is a secret message."

print("\nOriginal message:")
print(original_message)


# Akshatha encrypts
encrypted = akshatha.encrypt_message(
    original_message
)

print("\nEncrypted data:")
print(encrypted)


# Rahul decrypts
decrypted = rahul.decrypt_message(
    encrypted["nonce"],
    encrypted["ciphertext"]
)

print("\nDecrypted message:")
print(decrypted)


# Verify
if original_message == decrypted:

    print("\n================================")
    print("✅ MESSAGE ENCRYPTION SUCCESS")
    print("================================")

else:

    print("\n❌ MESSAGE ENCRYPTION FAILED")