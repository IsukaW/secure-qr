# SecureQR

A cross-platform secure QR code generator for Java and Node.js that encrypts data before encoding it into QR codes.

[![Maven Central](https://img.shields.io/maven-central/v/com.secureqr/secure-qr.svg)](https://search.maven.org/artifact/com.secureqr/secure-qr)
[![npm version](https://img.shields.io/npm/v/secure-qr.svg)](https://www.npmjs.com/package/secure-qr)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- Generate QR codes with AES-256 encrypted content
- Cross-platform compatibility between Java and Node.js
- Configurable encryption keys
- Export as PNG file or Base64 image string
- High error correction level for reliable scanning
- Simple API with intuitive methods

## Installation

### Java

#### Maven

Add the following dependency to your `pom.xml`:

```xml

    com.secureqr
    secure-qr
    1.0.0

```

#### Gradle

Add the following to your `build.gradle`:

```groovy
implementation 'com.secureqr:secure-qr:1.0.0'
```

### Node.js

Install via npm:

```bash
npm install secure-qr
```

## Usage

### Java

```java
import com.secureqr.SecureQR;
import java.nio.file.Paths;

// Generate a new encryption key
String encryptionKey = SecureQR.generateEncryptionKey(256);
System.out.println("Key: " + encryptionKey);

// Create SecureQR instance with the key
SecureQR secureQR = new SecureQR(encryptionKey);

// Generate encrypted QR code and save to file
secureQR.generateEncryptedQR("https://example.com/secure-data", 300, 300, 
        Paths.get("secure-qr.png"));

// Generate QR as Base64 string
String base64QR = secureQR.generateEncryptedQRBase64("https://example.com/secure-data", 300, 300);

// Decrypt QR data (after scanning)
String encryptedData = "..."; // Data from QR scan
String decryptedData = secureQR.decryptQR(encryptedData);
```

### Node.js

```javascript
const SecureQR = require('secure-qr');

// Generate a new encryption key
const encryptionKey = SecureQR.generateEncryptionKey(256);
console.log('Key:', encryptionKey);

// Create SecureQR instance with the key
const secureQR = new SecureQR(encryptionKey);

// Generate encrypted QR code and save to file
await secureQR.generateEncryptedQR('https://example.com/secure-data', {
  outPath: 'secure-qr.png',
  width: 300
});

// Generate QR as Base64 data URL
const base64QR = await secureQR.generateEncryptedQRBase64('https://example.com/secure-data');

// Decrypt QR data (after scanning)
const encryptedData = '...'; // Data from QR scan
const decryptedData = secureQR.decryptQR(encryptedData);
```

## API Reference

### Java API

#### Constructor

```java
public SecureQR(String encryptionKey)
```

- `encryptionKey`: Base64 encoded key (must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256)

#### Methods

```java
public void generateEncryptedQR(String data, int width, int height, Path filePath) throws Exception
```
- Encrypts `data` and generates a QR code image saved at `filePath`

```java
public String generateEncryptedQRBase64(String data, int width, int height) throws Exception
```
- Encrypts `data` and returns QR code as Base64 encoded image string

```java
public String encrypt(String data) throws Exception
```
- Encrypts `data` and returns Base64 encoded encrypted string

```java
public String decryptQR(String encryptedData) throws Exception
```
- Decrypts `encryptedData` and returns original plaintext

```java
public static String generateEncryptionKey(int keySize)
```
- Generates a random encryption key of specified size (128, 192, or 256 bits)

### Node.js API

#### Constructor

```javascript
new SecureQR(encryptionKey)
```

- `encryptionKey`: Base64 encoded key (must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256)

#### Methods

```javascript
async generateEncryptedQR(data, options = {})
```
- Encrypts `data` and generates a QR code
- `options`: Object with QR configuration (see QR options below)

```javascript
async generateEncryptedQRBase64(data, options = {})
```
- Encrypts `data` and returns QR code as Base64 data URL

```javascript
encrypt(data)
```
- Encrypts `data` and returns Base64 encoded encrypted string

```javascript
decryptQR(encryptedData)
```
- Decrypts `encryptedData` and returns original plaintext

```javascript
static generateEncryptionKey(keySize = 256)
```
- Generates a random encryption key of specified size (128, 192, or 256 bits)

#### QR Options (Node.js)

- `outPath`: File path to save the QR code (optional)
- `width`: Width of QR code in pixels (default: 300)
- `errorCorrectionLevel`: Error correction level (default: 'H')
- `margin`: White border around QR (default: 1)
- `color.dark`: Color of QR modules (default: '#000000')
- `color.light`: Background color (default: '#ffffff')

## Mobile App Integration

To read encrypted QR codes in your mobile app:

1. Scan the QR code using your preferred scanning library
2. Extract the encrypted data from the QR code
3. Use the same encryption key to decrypt the data

### Android Example

```java
// Assuming you've already scanned the QR and have the encrypted data
String encryptedData = qrScanResult;
SecureQR secureQR = new SecureQR(YOUR_ENCRYPTION_KEY);
String decryptedData = secureQR.decryptQR(encryptedData);
```

### iOS Example with Swift (using CryptoSwift)

Add the equivalent decryption function to your iOS app:

```swift
import CryptoSwift

func decryptQR(encryptedData: String, key: String) throws -> String {
    let data = Data(base64Encoded: encryptedData)!
    
    // Extract IV and ciphertext
    let iv = data.subdata(in: 0..<12)
    let authTag = data.subdata(in: data.count-16..<data.count)
    let ciphertext = data.subdata(in: 12..<data.count-16)
    
    // Decrypt using AES-GCM
    let keyData = Data(base64Encoded: key)!
    let aes = try AES(key: [UInt8](keyData), blockMode: GCM(iv: [UInt8](iv), authenticationTag: [UInt8](authTag)))
    let decryptedBytes = try aes.decrypt([UInt8](ciphertext))
    
    return String(bytes: decryptedBytes, encoding: .utf8)!
}
```

## Security Notes

1. **Key Management**: Store your encryption key securely. Consider using a key management service for production.

2. **Cross-Platform Compatibility**: The encryption implementations in Java and Node.js are designed to be compatible, using AES-GCM with the same parameters.

3. **Key Rotation**: Consider implementing key rotation for enhanced security.

## License

This project is licensed under the MIT License - see the LICENSE file for details.