import streamlit as st
import bcrypt

def hash_password(password):
    """Hashes a password using bcrypt."""
    # It's good practice to encode the password to bytes before hashing
    password_bytes = password.encode('utf-8')
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password.decode('utf-8') # Decode back to string for display

def verify_password(plain_password, hashed_password_str):
    """Verifies a plain password against a stored bcrypt hash."""
    plain_password_bytes = plain_password.encode('utf-8')
    hashed_password_bytes = hashed_password_str.encode('utf-8')
    return bcrypt.checkpw(plain_password_bytes, hashed_password_bytes)

# --- Streamlit App ---
st.set_page_config(page_title="Bcrypt Password Hasher", layout="centered")

st.title("🔑 Bcrypt Password Hashing Tool")
st.write("""
This tool demonstrates how bcrypt can be used to hash passwords.
Enter a password below to see its hashed version. You can also
verify a password against a known hash.
""")

# --- Hashing Section ---
st.header("Generate Bcrypt Hash")
password_to_hash = st.text_input("Enter password to hash:", type="password", key="hash_input")

if st.button("Hash Password", key="hash_button"):
    if password_to_hash:
        hashed_output = hash_password(password_to_hash)
        st.success("Password hashed successfully!")
        st.code(hashed_output, language=None) # Display the raw hash
        st.caption("This is the bcrypt hash of your password. Store this hash, not the plain password.")
    else:
        st.warning("Please enter a password to hash.")

st.markdown("---") # Separator

# --- Verification Section ---
st.header("Verify Password Against Hash")
password_to_verify = st.text_input("Enter plain password to verify:", type="password", key="verify_input")
known_hash = st.text_input("Enter known bcrypt hash:", key="verify_hash_input")

if st.button("Verify Password", key="verify_button"):
    if password_to_verify and known_hash:
        try:
            is_valid = verify_password(password_to_verify, known_hash)
            if is_valid:
                st.success("✅ Password matches the hash!")
            else:
                st.error("❌ Password does NOT match the hash.")
        except Exception as e:
            st.error(f"Error during verification: {e}")
            st.caption("Ensure the hash is a valid bcrypt hash string.")
    else:
        st.warning("Please enter both the plain password and the hash to verify.")

st.markdown("---")
st.info("""
**Important Security Notes:**
* **Salting:** `bcrypt.gensalt()` automatically generates a unique salt for each hash. This is crucial for security. The salt is embedded within the generated hash string itself.
* **Work Factor (Cost Factor):** `bcrypt.gensalt()` takes an optional `rounds` parameter (default is usually 12). Increasing this makes hashing slower and more resistant to brute-force attacks, but also increases server load.
* **Storing Hashes:** Never store plain-text passwords. Store the generated bcrypt hash.
* **Verification:** Use `bcrypt.checkpw()` to verify a user's input password against the stored hash.
""")
