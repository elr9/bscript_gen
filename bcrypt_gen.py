import streamlit as st
import bcrypt

# --- Core Bcrypt Functions ---
def hash_password(password):
    """Hashes a password using bcrypt."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt() # Generates a new salt each time
    hashed_password_bytes = bcrypt.hashpw(password_bytes, salt)
    return hashed_password_bytes.decode('utf-8') # Return as string

def verify_password(plain_password, hashed_password_str):
    """Verifies a plain password against a stored bcrypt hash."""
    plain_password_bytes = plain_password.encode('utf-8')
    hashed_password_bytes = hashed_password_str.encode('utf-8') # Encode stored hash string to bytes
    try:
        return bcrypt.checkpw(plain_password_bytes, hashed_password_bytes)
    except Exception as e:
        # bcrypt.checkpw can raise exceptions for malformed hashes (e.g., if not a valid bcrypt hash)
        st.error(f"Error during bcrypt.checkpw: {e}")
        return False

# --- Streamlit App ---
st.set_page_config(page_title="Bcrypt Password Hasher", layout="centered")

st.title("🔑 Bcrypt Password Hashing & Verification Tool")
st.write("""
This tool demonstrates bcrypt password hashing and verification.
""")

# --- Hashing and Immediate Internal Test Section ---
st.header("1. Generate Bcrypt Hash & Perform Internal Test")
password_to_hash = st.text_input("Enter password to hash:", type="password", key="hash_input_main")

if st.button("Hash Password & Run Internal Test", key="hash_and_test_button"):
    if password_to_hash:
        st.subheader("Hashing Process:")
        hashed_output_str = hash_password(password_to_hash)
        st.success("Password hashed successfully!")

        # Displaying the hash in two ways to help with copy-pasting
        st.write("Generated Hash (for copy-pasting):")
        st.code(hashed_output_str, language=None) # For display
        # st.text_area("Hash (selectable):", hashed_output_str, height=100, key="hash_display_area")


        st.caption(f"Hash details: Type: {type(hashed_output_str)}, Length: {len(hashed_output_str)}")
        st.markdown("---")

        st.subheader("Internal Verification Test:")
        st.write("Now, we will immediately try to verify the password you just entered (`", password_to_hash,"`) against the hash we just generated.")
        st.write("Generated hash being used for internal test:", hashed_output_str)

        # Use the original password and the freshly generated hash string
        is_internally_valid = verify_password(password_to_hash, hashed_output_str)

        if is_internally_valid:
            st.success("✅ SUCCESS: Internal verification passed! The original password matches the newly generated hash.")
            st.balloons()
        else:
            st.error("❌ FAILURE: Internal verification FAILED! There might be an issue in the hashing/verification logic or bcrypt setup.")
            st.write("This means `bcrypt.checkpw` returned `False` even when using the exact inputs programmatically.")
    else:
        st.warning("Please enter a password to hash.")

st.markdown("---")

# --- Manual Verification Section ---
st.header("2. Manually Verify Password Against a Known Hash")
st.write("You can use this section to verify a password against a hash you've copied (e.g., from the section above or elsewhere).")
password_to_verify = st.text_input("Enter plain password to verify:", type="password", key="verify_input_manual")
known_hash_manual = st.text_input("Paste known bcrypt hash here:", key="verify_hash_input_manual", placeholder="$2b$12$YourCopiedHashHere...")

if st.button("Verify Manually", key="verify_button_manual"):
    if password_to_verify and known_hash_manual:
        st.write(f"Attempting to verify password: '{password_to_verify}' against hash: '{known_hash_manual}'")
        st.caption(f"Pasted hash details: Type: {type(known_hash_manual)}, Length: {len(known_hash_manual)}")

        is_manually_valid = verify_password(password_to_verify, known_hash_manual)
        if is_manually_valid:
            st.success("✅ Password matches the provided hash!")
        else:
            st.error("❌ Password does NOT match the provided hash. Possible reasons: incorrect password, incorrect hash, or copy-paste errors in the hash (extra spaces, missing characters).")
            st.info("Tip: Ensure the hash string is copied exactly as generated. It should start with something like `$2a$` or `$2b$`.")
    elif not password_to_verify:
        st.warning("Please enter the plain password to verify.")
    elif not known_hash_manual:
        st.warning("Please enter the known bcrypt hash.")


st.markdown("---")
st.info("""
**Important Notes:**
* **Salting:** `bcrypt` automatically generates a unique salt for each hash and embeds it within the hash string. This means hashing the same password multiple times will produce *different* hash strings. However, `bcrypt.checkpw()` can correctly verify any of these valid hashes against the original password.
* **Copy-Pasting Hashes:** Be extremely careful. Extra spaces or missing characters will cause verification to fail. A bcrypt hash string is typically 59 or 60 characters long.
* **Independent Services:** If an independent service also fails, ensure you are pasting the exact, unaltered hash string.
""")
