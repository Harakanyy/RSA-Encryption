# Java RSA Encryption & Decryption

A lightweight Java implementation of the RSA cryptosystem supporting:

- **Key Generation** (`RSAGenKey.java`)  
  - Generate an RSA keypair (`public.key` & `private.key`) of configurable bit-length
- **Encryption** (`RSAEncrypt.java`)  
  - Encrypt any file or text payload using the recipient’s public key
- **Decryption** (`RSADecrypt.java`)  
  - Decrypt a cipher file back to its original plaintext using the private key
- **Bonus (Authentication & Confidentiality)** (`DoubleCrypto.java`)  
  - Sign & encrypt (double-lock) for both authenticity and privacy
- **Future Network Integration** (`NetworkHandler.java`)  
  - Stub methods to send/receive encrypted payloads over sockets

---

## 🚀 Features

1. **Configurable Key Sizes**  
   Generate 1024, 2048, or larger keys securely via `BigInteger.probablePrime()`.  
2. **CLI-Driven**  
   All tools accept command-line flags for input/output paths and key sizes.  
3. **No External Dependencies**  
   Pure JDK solution leveraging `java.math.BigInteger`.  
4. **Extensible Design**  
   Clear class separation for easy integration into networked applications.

---
## Prerequisites
- Java 11+ installed

## Build & Run (plain javac)
```bash
# compile all Java files
javac -d out src/main/java/rsa/*.java

# generate keys
java -cp out rsa.RSAGenKey

# encrypt
java -cp out rsa.RSAEncrypt plaintext.txt keys/public.key ciphertext.bin

# decrypt
java -cp out rsa.RSADecrypt ciphertext.bin keys/private.key recovered.txt
