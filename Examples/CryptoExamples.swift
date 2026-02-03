import Foundation
import CryptoKit
#if canImport(SwiftCryptoPro)
import SwiftCryptoPro
#endif

// MARK: - Cryptography Usage Examples

/// Comprehensive examples demonstrating SwiftCrypto-Pro capabilities.
///
/// This file contains practical examples for common cryptographic operations
/// including encryption, hashing, key management, and authentication.

// MARK: - AES-GCM Encryption Examples

/// Demonstrates AES-GCM authenticated encryption.
enum AESGCMExamples {
    
    /// Basic string encryption and decryption.
    static func basicEncryption() throws {
        print("=== AES-GCM Basic Encryption ===\n")
        
        // Generate a 256-bit key
        let key = SymmetricKey(size: .bits256)
        
        // Create encryptor
        let encryptor = AESGCMEncryptor(key: key)
        
        // Encrypt a message
        let plaintext = "Hello, World! This is a secret message."
        let encrypted = try encryptor.encrypt(plaintext)
        
        print("Original: \(plaintext)")
        print("Encrypted (base64): \(encrypted.base64EncodedString())")
        
        // Decrypt
        let decrypted = try encryptor.decryptToString(encrypted)
        print("Decrypted: \(decrypted)")
        
        // Verify
        assert(plaintext == decrypted, "Decryption failed!")
        print("\n✓ Encryption/decryption successful\n")
    }
    
    /// Encryption with associated data (AAD).
    static func encryptionWithAAD() throws {
        print("=== AES-GCM with Associated Data ===\n")
        
        let key = SymmetricKey(size: .bits256)
        let encryptor = AESGCMEncryptor(key: key)
        
        // The message to encrypt
        let message = "Sensitive financial data"
        let messageData = message.data(using: .utf8)!
        
        // Associated data (authenticated but not encrypted)
        let header = "transaction-id:12345"
        let aad = header.data(using: .utf8)!
        
        // Encrypt with AAD
        let sealedBox = try AES.GCM.seal(
            messageData,
            using: key,
            authenticating: aad
        )
        
        print("Message: \(message)")
        print("Header (AAD): \(header)")
        print("Ciphertext: \(sealedBox.ciphertext.base64EncodedString())")
        print("Tag: \(sealedBox.tag.base64EncodedString())")
        
        // Decrypt with same AAD
        let decrypted = try AES.GCM.open(sealedBox, using: key, authenticating: aad)
        print("Decrypted: \(String(data: decrypted, encoding: .utf8)!)")
        print("\n✓ AAD encryption successful\n")
    }
    
    /// File encryption example.
    static func fileEncryption() throws {
        print("=== File Encryption ===\n")
        
        // Simulate file content
        let fileContent = """
        {
            "users": [
                {"id": 1, "name": "Alice", "email": "alice@example.com"},
                {"id": 2, "name": "Bob", "email": "bob@example.com"}
            ],
            "metadata": {
                "created": "2024-01-15",
                "version": "1.0"
            }
        }
        """
        
        let key = SymmetricKey(size: .bits256)
        let encryptor = AESGCMEncryptor(key: key)
        
        // Encrypt
        let fileData = fileContent.data(using: .utf8)!
        let encryptedFile = try encryptor.encrypt(fileData)
        
        print("Original size: \(fileData.count) bytes")
        print("Encrypted size: \(encryptedFile.count) bytes")
        print("Overhead: \(encryptedFile.count - fileData.count) bytes (nonce + tag)")
        
        // Decrypt
        let decryptedFile = try encryptor.decrypt(encryptedFile)
        let recoveredContent = String(data: decryptedFile, encoding: .utf8)!
        
        assert(fileContent == recoveredContent)
        print("\n✓ File encryption successful\n")
    }
}

// MARK: - ChaCha20-Poly1305 Examples

/// Demonstrates ChaCha20-Poly1305 authenticated encryption.
enum ChaCha20Examples {
    
    /// Basic ChaCha20-Poly1305 usage.
    static func basicUsage() throws {
        print("=== ChaCha20-Poly1305 Encryption ===\n")
        
        let key = SymmetricKey(size: .bits256)
        let encryptor = ChaCha20Poly1305Encryptor(key: key)
        
        let message = "ChaCha20 is great for mobile devices!"
        let encrypted = try encryptor.encrypt(message)
        let decrypted = try encryptor.decryptToString(encrypted)
        
        print("Original: \(message)")
        print("Encrypted: \(encrypted.base64EncodedString())")
        print("Decrypted: \(decrypted)")
        print("\n✓ ChaCha20-Poly1305 successful\n")
    }
    
    /// Streaming encryption for large data.
    static func streamingEncryption() throws {
        print("=== Streaming Encryption ===\n")
        
        let key = SymmetricKey(size: .bits256)
        
        // Simulate large data in chunks
        let chunks = [
            "First chunk of data...",
            "Second chunk of data...",
            "Third chunk of data...",
            "Final chunk!"
        ]
        
        var encryptedChunks: [Data] = []
        
        for (index, chunk) in chunks.enumerated() {
            let nonce = try ChaChaPoly.Nonce(data: Data(count: 12))
            let sealed = try ChaChaPoly.seal(
                chunk.data(using: .utf8)!,
                using: key,
                nonce: nonce
            )
            encryptedChunks.append(sealed.combined!)
            print("Chunk \(index + 1): \(chunk.count) bytes → \(sealed.combined!.count) bytes")
        }
        
        print("\n✓ Streaming encryption complete\n")
    }
}

// MARK: - Hashing Examples

/// Demonstrates cryptographic hashing operations.
enum HashingExamples {
    
    /// Basic hashing with various algorithms.
    static func basicHashing() {
        print("=== Cryptographic Hashing ===\n")
        
        let message = "The quick brown fox jumps over the lazy dog"
        let messageData = message.data(using: .utf8)!
        
        // SHA-256
        let sha256 = SHA256.hash(data: messageData)
        print("SHA-256: \(sha256.compactMap { String(format: "%02x", $0) }.joined())")
        
        // SHA-384
        let sha384 = SHA384.hash(data: messageData)
        print("SHA-384: \(sha384.compactMap { String(format: "%02x", $0) }.joined())")
        
        // SHA-512
        let sha512 = SHA512.hash(data: messageData)
        print("SHA-512: \(sha512.compactMap { String(format: "%02x", $0) }.joined())")
        
        print("\n✓ Hashing complete\n")
    }
    
    /// HMAC message authentication.
    static func hmacAuthentication() {
        print("=== HMAC Authentication ===\n")
        
        let key = SymmetricKey(size: .bits256)
        let message = "Important message to authenticate"
        let messageData = message.data(using: .utf8)!
        
        // Generate HMAC
        let hmac = HMAC<SHA256>.authenticationCode(for: messageData, using: key)
        let hmacHex = Data(hmac).map { String(format: "%02x", $0) }.joined()
        
        print("Message: \(message)")
        print("HMAC-SHA256: \(hmacHex)")
        
        // Verify HMAC
        let isValid = HMAC<SHA256>.isValidAuthenticationCode(
            Data(hmac),
            authenticating: messageData,
            using: key
        )
        
        print("Verification: \(isValid ? "✓ Valid" : "✗ Invalid")")
        print("\n")
    }
    
    /// File integrity verification.
    static func fileIntegrity() {
        print("=== File Integrity Check ===\n")
        
        let originalContent = "This is the original file content"
        let originalData = originalContent.data(using: .utf8)!
        
        // Calculate checksum
        let checksum = SHA256.hash(data: originalData)
        let checksumHex = checksum.compactMap { String(format: "%02x", $0) }.joined()
        
        print("Original content: \"\(originalContent)\"")
        print("SHA-256 checksum: \(checksumHex)")
        
        // Verify unchanged content
        let verifyData = originalContent.data(using: .utf8)!
        let verifyChecksum = SHA256.hash(data: verifyData)
        
        let isIntact = checksumHex == verifyChecksum.compactMap { String(format: "%02x", $0) }.joined()
        print("Integrity check: \(isIntact ? "✓ File intact" : "✗ File modified")")
        
        // Simulate tampered content
        let tamperedContent = "This is the modified file content"
        let tamperedData = tamperedContent.data(using: .utf8)!
        let tamperedChecksum = SHA256.hash(data: tamperedData)
        let tamperedHex = tamperedChecksum.compactMap { String(format: "%02x", $0) }.joined()
        
        let isTampered = checksumHex != tamperedHex
        print("Tamper detection: \(isTampered ? "✓ Tampering detected" : "✗ Not detected")")
        print("\n")
    }
}

// MARK: - Key Derivation Examples

/// Demonstrates password-based key derivation.
enum KeyDerivationExamples {
    
    /// PBKDF2 key derivation.
    static func pbkdf2Example() throws {
        print("=== PBKDF2 Key Derivation ===\n")
        
        let password = "MySecurePassword123!"
        let pbkdf2 = PBKDF2()
        
        // Derive a key with automatic salt generation
        let result = try pbkdf2.deriveKey(
            password: password,
            iterations: 100_000,
            keyLength: 32,
            algorithm: .sha256
        )
        
        print("Password: \(password)")
        print("Salt: \(result.hexSalt)")
        print("Derived Key: \(result.hexKey)")
        print("Iterations: \(result.iterations)")
        print("Storable: \(result.storable)")
        
        // Verify password
        let isValid = try pbkdf2.verify(
            password: password,
            salt: result.salt,
            expectedKey: result.derivedKey,
            iterations: result.iterations,
            algorithm: .sha256
        )
        
        print("Password verification: \(isValid ? "✓ Valid" : "✗ Invalid")")
        print("\n")
    }
    
    /// Password hashing for storage.
    static func passwordHashingExample() throws {
        print("=== Password Hashing ===\n")
        
        let pbkdf2 = PBKDF2(configuration: .highSecurity)
        
        // Hash a password
        let password = "User'sSecretPassword"
        let hash = try pbkdf2.hashPassword(password)
        
        print("Password: \(password)")
        print("Hash: \(hash)")
        
        // Verify correct password
        let correctVerify = try pbkdf2.verifyPassword(password, against: hash)
        print("Correct password: \(correctVerify ? "✓ Match" : "✗ No match")")
        
        // Verify wrong password
        let wrongVerify = try pbkdf2.verifyPassword("WrongPassword", against: hash)
        print("Wrong password: \(wrongVerify ? "✗ Match (error!)" : "✓ No match")")
        print("\n")
    }
    
    /// Key derivation for encryption.
    static func deriveEncryptionKey() throws {
        print("=== Derive Encryption Key ===\n")
        
        let password = "EncryptionPassword"
        let salt = SecureRandom.salt(bytes: 32)
        
        let pbkdf2 = PBKDF2()
        let symmetricKey = try pbkdf2.deriveSymmetricKey(
            password: password,
            salt: salt,
            iterations: 100_000
        )
        
        print("Derived symmetric key from password")
        print("Key size: 256 bits")
        
        // Use derived key for encryption
        let encryptor = AESGCMEncryptor(key: symmetricKey)
        let message = "Encrypted with password-derived key"
        let encrypted = try encryptor.encrypt(message)
        let decrypted = try encryptor.decryptToString(encrypted)
        
        print("Message: \(message)")
        print("Decrypted: \(decrypted)")
        print("✓ Password-based encryption successful\n")
    }
}

// MARK: - Digital Signature Examples

/// Demonstrates digital signature operations.
enum SignatureExamples {
    
    /// ECDSA signing and verification.
    static func ecdsaExample() throws {
        print("=== ECDSA Digital Signatures ===\n")
        
        let signer = ECDSASigner()
        
        // Generate key pair
        let keyPair = signer.generateKeyPair()
        print("Generated P-256 key pair")
        
        // Sign a message
        let message = "This document is legally binding"
        let signature = try signer.sign(message, privateKey: keyPair.privateKey)
        
        print("Message: \(message)")
        print("Signature: \(signature.base64EncodedString())")
        
        // Verify signature
        let isValid = signer.verify(
            message,
            signature: signature,
            publicKey: keyPair.publicKey
        )
        
        print("Verification: \(isValid ? "✓ Valid signature" : "✗ Invalid signature")")
        
        // Tampered message verification
        let tamperedValid = signer.verify(
            "This document is NOT legally binding",
            signature: signature,
            publicKey: keyPair.publicKey
        )
        
        print("Tampered verification: \(tamperedValid ? "✗ Still valid (error!)" : "✓ Rejected")")
        print("\n")
    }
    
    /// Document signing workflow.
    static func documentSigning() throws {
        print("=== Document Signing Workflow ===\n")
        
        // Simulate a document
        let document = """
        CONTRACT AGREEMENT
        
        This agreement is made on \(Date())
        Between Party A and Party B...
        
        [Document content here]
        """
        
        let signer = ECDSASigner()
        let keyPair = signer.generateKeyPair()
        
        // Hash the document
        let documentData = document.data(using: .utf8)!
        let documentHash = SHA256.hash(data: documentData)
        let hashData = Data(documentHash)
        
        print("Document hash: \(hashData.map { String(format: "%02x", $0) }.joined().prefix(32))...")
        
        // Sign the hash
        let signature = try signer.sign(hashData, privateKey: keyPair.privateKey)
        
        print("Signature created")
        print("Signature length: \(signature.count) bytes")
        
        // Verification (would be done by recipient)
        let verified = signer.verify(
            hashData,
            signature: signature,
            publicKey: keyPair.publicKey
        )
        
        print("Document verification: \(verified ? "✓ Authentic" : "✗ Tampered")")
        print("\n")
    }
}

// MARK: - Key Agreement Examples

/// Demonstrates ECDH key agreement.
enum KeyAgreementExamples {
    
    /// Basic ECDH key exchange.
    static func ecdhKeyExchange() throws {
        print("=== ECDH Key Exchange ===\n")
        
        // Alice generates her key pair
        let alicePrivateKey = P256.KeyAgreement.PrivateKey()
        let alicePublicKey = alicePrivateKey.publicKey
        
        // Bob generates his key pair
        let bobPrivateKey = P256.KeyAgreement.PrivateKey()
        let bobPublicKey = bobPrivateKey.publicKey
        
        print("Alice and Bob exchange public keys...")
        
        // Alice derives shared secret using Bob's public key
        let aliceSharedSecret = try alicePrivateKey.sharedSecretFromKeyAgreement(
            with: bobPublicKey
        )
        
        // Bob derives shared secret using Alice's public key
        let bobSharedSecret = try bobPrivateKey.sharedSecretFromKeyAgreement(
            with: alicePublicKey
        )
        
        // Derive symmetric keys from shared secrets
        let aliceKey = aliceSharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data("encryption".utf8),
            outputByteCount: 32
        )
        
        let bobKey = bobSharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data("encryption".utf8),
            outputByteCount: 32
        )
        
        // Verify keys match by encrypting/decrypting
        let testMessage = "Secret message from Alice to Bob"
        let messageData = testMessage.data(using: .utf8)!
        
        // Alice encrypts with her derived key
        let sealed = try AES.GCM.seal(messageData, using: aliceKey)
        
        // Bob decrypts with his derived key
        let decrypted = try AES.GCM.open(sealed, using: bobKey)
        let decryptedMessage = String(data: decrypted, encoding: .utf8)!
        
        print("Alice's message: \(testMessage)")
        print("Bob received: \(decryptedMessage)")
        print("Key agreement: \(testMessage == decryptedMessage ? "✓ Success" : "✗ Failed")")
        print("\n")
    }
}

// MARK: - Secure Random Examples

/// Demonstrates secure random generation.
enum SecureRandomExamples {
    
    /// Various random generation examples.
    static func randomGeneration() throws {
        print("=== Secure Random Generation ===\n")
        
        // Random bytes
        let randomBytes = try SecureRandom.bytes(count: 16)
        print("Random bytes: \(randomBytes.map { String(format: "%02x", $0) }.joined())")
        
        // Random integers
        let randomInt = SecureRandom.int(in: 1...100)
        print("Random int (1-100): \(randomInt)")
        
        // Random double
        let randomDouble = SecureRandom.double(in: 0.0...1.0)
        print("Random double (0-1): \(String(format: "%.6f", randomDouble))")
        
        // Random boolean
        let randomBool = SecureRandom.bool()
        print("Random boolean: \(randomBool)")
        
        print("\n")
    }
    
    /// String and password generation.
    static func stringGeneration() throws {
        print("=== Random String Generation ===\n")
        
        // Alphanumeric string
        let alphanumeric = SecureRandom.alphanumeric(length: 20)
        print("Alphanumeric: \(alphanumeric)")
        
        // Hex string
        let hexString = SecureRandom.hex(length: 32)
        print("Hex: \(hexString)")
        
        // URL-safe token
        let token = SecureRandom.token(length: 24)
        print("Token: \(token)")
        
        // Password
        let password = SecureRandom.password(length: 16, includeSymbols: true)
        print("Password: \(password)")
        
        // Passphrase
        let passphrase = SecureRandom.passphrase(wordCount: 4, separator: "-")
        print("Passphrase: \(passphrase)")
        
        // UUID
        let uuid = SecureRandom.uuidString()
        print("UUID: \(uuid)")
        
        print("\n")
    }
    
    /// Cryptographic key material.
    static func keyMaterial() {
        print("=== Cryptographic Key Material ===\n")
        
        // Symmetric key
        let key = SecureRandom.symmetricKey(bits: 256)
        print("Generated 256-bit symmetric key")
        
        // IV for AES-GCM
        let iv = SecureRandom.iv(bytes: 12)
        print("IV: \(iv.map { String(format: "%02x", $0) }.joined())")
        
        // Nonce
        let nonce = SecureRandom.nonce(bytes: 12)
        print("Nonce: \(nonce.map { String(format: "%02x", $0) }.joined())")
        
        // Salt for key derivation
        let salt = SecureRandom.salt(bytes: 32)
        print("Salt: \(salt.map { String(format: "%02x", $0) }.joined())")
        
        print("\n")
    }
}

// MARK: - Keychain Examples

/// Demonstrates keychain storage operations.
enum KeychainExamples {
    
    /// Basic keychain operations.
    static func basicOperations() throws {
        print("=== Keychain Storage ===\n")
        
        let keychain = KeychainWrapper(service: "com.example.demo")
        
        // Store a password
        try keychain.set("MySecretPassword", forKey: "user_password")
        print("✓ Stored password")
        
        // Retrieve password
        if let password = try keychain.getString(forKey: "user_password") {
            print("✓ Retrieved password: \(password)")
        }
        
        // Store a Codable object
        struct UserCredentials: Codable {
            let username: String
            let accessToken: String
            let refreshToken: String
        }
        
        let credentials = UserCredentials(
            username: "john_doe",
            accessToken: "access_token_123",
            refreshToken: "refresh_token_456"
        )
        
        try keychain.set(credentials, forKey: "user_credentials")
        print("✓ Stored credentials object")
        
        // Retrieve Codable object
        if let retrieved = try keychain.get("user_credentials", as: UserCredentials.self) {
            print("✓ Retrieved: \(retrieved.username)")
        }
        
        // Check existence
        let exists = keychain.contains(key: "user_password")
        print("Key exists: \(exists)")
        
        // List all keys
        let allKeys = keychain.allKeys()
        print("All keys: \(allKeys)")
        
        // Cleanup
        try keychain.deleteAll()
        print("✓ Cleaned up\n")
    }
}

// MARK: - TOTP Examples

/// Demonstrates Time-based One-Time Password generation.
enum TOTPExamples {
    
    /// Basic TOTP generation.
    static func basicTOTP() {
        print("=== TOTP Generation ===\n")
        
        let generator = TOTPGenerator()
        
        // Generate a secret
        let secret = "JBSWY3DPEHPK3PXP"  // Base32 encoded
        
        // Generate current TOTP
        let totp = generator.generate(secret: secret)
        
        print("Secret: \(secret)")
        print("Current TOTP: \(totp)")
        print("Valid for: ~30 seconds")
        
        // Generate provisioning URI for QR code
        let uri = generator.provisioningURI(
            secret: secret,
            accountName: "user@example.com",
            issuer: "MyApp"
        )
        print("Provisioning URI: \(uri)")
        print("\n")
    }
}

// MARK: - Run All Examples

/// Runs all example demonstrations.
public func runAllExamples() {
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║           SwiftCrypto-Pro Usage Examples                     ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")
    
    do {
        // AES-GCM
        try AESGCMExamples.basicEncryption()
        try AESGCMExamples.encryptionWithAAD()
        try AESGCMExamples.fileEncryption()
        
        // ChaCha20
        try ChaCha20Examples.basicUsage()
        
        // Hashing
        HashingExamples.basicHashing()
        HashingExamples.hmacAuthentication()
        HashingExamples.fileIntegrity()
        
        // Key Derivation
        try KeyDerivationExamples.pbkdf2Example()
        try KeyDerivationExamples.passwordHashingExample()
        try KeyDerivationExamples.deriveEncryptionKey()
        
        // Signatures
        try SignatureExamples.ecdsaExample()
        try SignatureExamples.documentSigning()
        
        // Key Agreement
        try KeyAgreementExamples.ecdhKeyExchange()
        
        // Secure Random
        try SecureRandomExamples.randomGeneration()
        try SecureRandomExamples.stringGeneration()
        SecureRandomExamples.keyMaterial()
        
        // Keychain
        try KeychainExamples.basicOperations()
        
        // TOTP
        TOTPExamples.basicTOTP()
        
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                 All Examples Completed!                       ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        
    } catch {
        print("Error: \(error.localizedDescription)")
    }
}
