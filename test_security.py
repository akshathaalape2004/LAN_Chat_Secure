from security import Identity


print("Creating Akshatha identity...")
akshatha = Identity("Akshatha")

print("Creating Rahul identity...")
rahul = Identity("Rahul")


akshatha_public = akshatha.get_public_key()
rahul_public = rahul.get_public_key()


print("\nEd25519 public keys generated.")

print(
    "Akshatha public key:",
    akshatha_public
)

print(
    "Rahul public key:",
    rahul_public
)


# =====================================================
# AKSHATHA SIGNS A MESSAGE
# =====================================================

message = "Akshatha wants to connect with Rahul"

signature = akshatha.sign(
    message
)

print("\nMessage:")
print(message)

print("\nSignature:")
print(signature)


# =====================================================
# RAHUL VERIFIES AKSHATHA
# =====================================================

valid = Identity.verify(
    akshatha_public,
    signature,
    message
)

if valid:

    print("\n================================")
    print("✅ ED25519 AUTHENTICATION SUCCESS")
    print("================================")

else:

    print("\n❌ AUTHENTICATION FAILED")


# =====================================================
# TEST TAMPERED MESSAGE
# =====================================================

tampered_message = (
    "Akshatha wants to connect with ATTACKER"
)

valid = Identity.verify(
    akshatha_public,
    signature,
    tampered_message
)

if not valid:

    print("\n================================")
    print("✅ TAMPER DETECTION SUCCESS")
    print("================================")

else:

    print("\n❌ SECURITY ERROR")