const SecureQR = require('./secure-qr');
const fs = require('fs');

async function runExample() {
  try {
    // Generate or use an existing encryption key (AES-256)
    const encryptionKey = SecureQR.generateEncryptionKey(256);
    console.log('Generated Encryption Key:', encryptionKey);
    
    // Create SecureQR instance with the key
    const secureQR = new SecureQR(encryptionKey);
    
    // Data to encode in QR code
    const originalData = 'https://example.com/secure-resource?id=12345';
    
    // Generate QR code and save to file
    const qrCodePath = await secureQR.generateEncryptedQR(originalData, {
      outPath: 'secure-qr-code.png',
      width: 300
    });
    console.log('QR code generated and saved to:', qrCodePath);
    
    // Generate QR code as Base64 string (data URL)
    const base64QR = await secureQR.generateEncryptedQRBase64(originalData, {
      width: 300
    });
    console.log('Base64 QR code (data URL):', base64QR.substring(0, 50) + '...');
    
    // Simulate reading encrypted data from QR code
    // In a real app, you would scan the QR code to get the encrypted data
    const encryptedData = secureQR.encrypt(originalData);
    console.log('Encrypted data:', encryptedData);
    
    // Decrypt the data
    const decryptedData = secureQR.decryptQR(encryptedData);
    console.log('Decrypted data:', decryptedData);
    
    // Verify the decryption was successful
    console.log('Decryption successful:', originalData === decryptedData);
    
  } catch (error) {
    console.error('Error:', error);
  }
}

// Run the example
runExample();