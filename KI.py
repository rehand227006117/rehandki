import streamlit as st

def key_scheduling(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def pseudo_random_generation(S, length):
    i, j = 0, 0
    key_stream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        key_stream.append(S[(S[i] + S[j]) % 256])
    return key_stream

def rc4_encrypt(plaintext, key):
    key_stream = pseudo_random_generation(key_scheduling(key), len(plaintext))
    ciphertext = [chr(ord(plaintext[i]) ^ key_stream[i]) for i in range(len(plaintext))]
    return ''.join(ciphertext)

def rc4_decrypt(ciphertext, key):
    return rc4_encrypt(ciphertext, key)  # RC4 decryption is the same as encryption

def main():
    st.text(" By.Rehand Naifisurya H (227006117)")
    st.header("RC4 Enkripsi")

    # Input fields
    plaintext = st.text_input("Masukkan plaintext:", " ")
    key = st.text_input("Masukkan key (Dalam Bentuk Heksa C:/ 1A,2B,3C,4D,5E):", "16")

    # Convert key to list of integers
    key_convert = [int(val, 16) for val in key.split(",")]

    # Encrypt and decrypt
    encrypted_text = rc4_encrypt(plaintext, key_convert)    
    decrypted_text = rc4_decrypt(encrypted_text, key_convert)

    if st.button("Enkripsikan"):
        st.write(f"Plaintext: {plaintext}")
        st.write(f"Ciphertext: {encrypted_text}")
        st.write(f"Key: {key}")

    
    if st.checkbox("Tampilkan Proses Dekripsi"):  
        st.write("---")
        st.header("RC4 Dekripsi")
        encrypted_text = st.text_input("Masukkan Ciphertext:", value = encrypted_text)
        key2 = st.text_input("Masukan key (Dalam Bentuk Heksa):", value = key)
        if key != key2 :
            st.write("Key Salah")
        elif key == key2 :
            key2 = [int(val, 16) for val in key2.split(",")]
            if st.button("Dekripsikan"):
                st.write(f"Ciphertext: {encrypted_text}")
                st.write(f"Plaintext: {decrypted_text}")
            

if __name__ == "__main__":
    main()
