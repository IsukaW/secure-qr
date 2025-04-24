package com.secureqr.example;

import com.secureqr.SecureQR;
import java.nio.file.Paths;

public class SecureQRExample {
    
    public static void main(String[] args) {
        try {
            // Generate or use an existing encryption key (AES-256)
            String encryptionKey = SecureQR.generateEncryptionKey(256);
            System.out.println("Generated Encryption Key: " + encryptionKey);
            
            // Create SecureQR instance with the key
            SecureQR secureQR = new SecureQR(encryptionKey);
            
            // Data to encode in QR code
            String originalData = "https://example.com/secure-resource?id=12345";
            
            // Generate QR code and save to file
            secureQR.generateEncryptedQR(originalData, 300, 300, 
                    Paths.get("secure-qr-code.png"));
            System.out.println("QR code generated and saved to file");
            
            // Generate QR code as Base64 string
            String base64QR = secureQR.generateEncryptedQRBase64(originalData, 300, 300);
            System.out.println("Base64 QR code: " + base64QR.substring(0, 50) + "...");
            
            // Simulate reading encrypted data from QR code
            // In a real app, you would scan the QR code to get the encrypted data
            String encryptedData = secureQR.encrypt(originalData);
            System.out.println("Encrypted data: " + encryptedData);
            
            // Decrypt the data
            String decryptedData = secureQR.decryptQR(encryptedData);
            System.out.println("Decrypted data: " + decryptedData);
            
            // Verify the decryption was successful
            System.out.println("Decryption successful: " + originalData.equals(decryptedData));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}