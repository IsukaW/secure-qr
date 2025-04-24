package com.secureqr;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class SecureQR {
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private SecretKey secretKey;

    /**
     * Initialize SecureQR with the given encryption key
     * 
     * @param encryptionKey Base64 encoded key (must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
     */
    public SecureQR(String encryptionKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encryptionKey);
        this.secretKey = new SecretKeySpec(decodedKey, "AES");
    }

    /**
     * Generate a secure QR code from the given data
     * 
     * @param data The data to encode in the QR code
     * @param width Width of the QR code image
     * @param height Height of the QR code image
     * @param filePath Path to save the QR code image
     * @throws Exception If encryption or QR generation fails
     */
    public void generateEncryptedQR(String data, int width, int height, Path filePath) throws Exception {
        String encryptedData = encrypt(data);
        generateQRCode(encryptedData, width, height, filePath);
    }

    /**
     * Generate a secure QR code and return as Base64 encoded image
     * 
     * @param data The data to encode in the QR code
     * @param width Width of the QR code image
     * @param height Height of the QR code image
     * @return Base64 encoded image string
     * @throws Exception If encryption or QR generation fails
     */
    public String generateEncryptedQRBase64(String data, int width, int height) throws Exception {
        String encryptedData = encrypt(data);
        return generateQRCodeBase64(encryptedData, width, height);
    }

    /**
     * Encrypt the given data using AES-GCM
     * 
     * @param data The data to encrypt
     * @return Base64 encoded encrypted data with IV prepended
     * @throws Exception If encryption fails
     */
    public String encrypt(String data) throws Exception {
        // Generate a random IV (Initialization Vector)
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        
        // Initialize cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // Encrypt the data
        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        
        // Combine IV and encrypted data
        byte[] combined = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedData, 0, combined, iv.length, encryptedData.length);
        
        // Return Base64 encoded result
        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Decrypt the encrypted data from a QR code
     * 
     * @param encryptedData Base64 encoded encrypted data
     * @return Original plaintext data
     * @throws Exception If decryption fails
     */
    public String decryptQR(String encryptedData) throws Exception {
        // Decode the Base64 string
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        
        // Extract IV and ciphertext
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] ciphertext = new byte[decodedData.length - GCM_IV_LENGTH];
        
        System.arraycopy(decodedData, 0, iv, 0, iv.length);
        System.arraycopy(decodedData, iv.length, ciphertext, 0, ciphertext.length);
        
        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        
        // Decrypt the data
        byte[] decryptedData = cipher.doFinal(ciphertext);
        
        // Return the original plaintext
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    /**
     * Generate a QR code from the given data
     * 
     * @param data The data to encode in the QR code
     * @param width Width of the QR code image
     * @param height Height of the QR code image 
     * @param filePath Path to save the QR code image
     * @throws WriterException If QR code generation fails
     * @throws IOException If file writing fails
     */
    private void generateQRCode(String data, int width, int height, Path filePath) 
            throws WriterException, IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.H);
        hints.put(EncodeHintType.MARGIN, 1);
        
        BitMatrix bitMatrix = qrCodeWriter.encode(data, BarcodeFormat.QR_CODE, width, height, hints);
        
        // Write to file
        MatrixToImageWriter.writeToPath(bitMatrix, "PNG", filePath);
    }

    /**
     * Generate a QR code and return as Base64 encoded image
     * 
     * @param data The data to encode in the QR code
     * @param width Width of the QR code image
     * @param height Height of the QR code image
     * @return Base64 encoded image string
     * @throws WriterException If QR code generation fails
     * @throws IOException If encoding fails
     */
    private String generateQRCodeBase64(String data, int width, int height) 
            throws WriterException, IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.H);
        hints.put(EncodeHintType.MARGIN, 1);
        
        BitMatrix bitMatrix = qrCodeWriter.encode(data, BarcodeFormat.QR_CODE, width, height, hints);
        
        // Write to ByteArrayOutputStream
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
        
        // Convert to Base64
        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
    }

    /**
     * Utility method to generate a random encryption key
     * 
     * @param keySize Size of the key in bits (128, 192, or 256)
     * @return Base64 encoded encryption key
     */
    public static String generateEncryptionKey(int keySize) {
        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw new IllegalArgumentException("Key size must be 128, 192, or 256 bits");
        }
        
        byte[] key = new byte[keySize / 8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);
        
        return Base64.getEncoder().encodeToString(key);
    }
}