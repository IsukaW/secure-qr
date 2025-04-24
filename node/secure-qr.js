const crypto = require('crypto');
const qrcode = require('qrcode');

class SecureQR {
  /**
   * Initialize SecureQR with the given encryption key
   * 
   * @param {string} encryptionKey - Base64 encoded key (must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
   */
  constructor(encryptionKey) {
    this.secretKey = Buffer.from(encryptionKey, 'base64');
    this.algorithm = 'aes-256-gcm';
    this.ivLength = 12; // For GCM mode
  }

  /**
   * Encrypt the given data using AES-GCM
   * 
   * @param {string} data - The data to encrypt
   * @returns {string} Base64 encoded encrypted data with IV prepended
   */
  encrypt(data) {
    // Generate a random IV (Initialization Vector)
    const iv = crypto.randomBytes(this.ivLength);
    
    // Create cipher with key and IV
    const cipher = crypto.createCipheriv(this.algorithm, this.secretKey, iv);
    
    // Encrypt the data
    let encrypted = cipher.update(data, 'utf8', 'binary');
    encrypted += cipher.final('binary');
    
    // Get the authentication tag
    const authTag = cipher.getAuthTag();
    
    // Combine IV, encrypted data and auth tag
    const combined = Buffer.concat([
      iv,
      Buffer.from(encrypted, 'binary'),
      authTag
    ]);
    
    // Return as Base64 encoded string
    return combined.toString('base64');
  }

  /**
   * Decrypt the encrypted data from a QR code
   * 
   * @param {string} encryptedData - Base64 encoded encrypted data
   * @returns {string} Original plaintext data
   */
  decryptQR(encryptedData) {
    // Decode the Base64 string
    const buffer = Buffer.from(encryptedData, 'base64');
    
    // Extract IV, ciphertext and auth tag
    const iv = buffer.slice(0, this.ivLength);
    const authTag = buffer.slice(buffer.length - 16); // Last 16 bytes are the auth tag
    const encrypted = buffer.slice(this.ivLength, buffer.length - 16);
    
    // Create decipher
    const decipher = crypto.createDecipheriv(this.algorithm, this.secretKey, iv);
    decipher.setAuthTag(authTag);
    
    // Decrypt the data
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    // Return the original plaintext
    return decrypted.toString('utf8');
  }

  /**
   * Generate a secure QR code from the given data
   * 
   * @param {string} data - The data to encode in the QR code
   * @param {Object} options - QR code options
   * @returns {Promise<string>} - Path to the generated QR code file
   */
  async generateEncryptedQR(data, options = {}) {
    const defaultOptions = {
      errorCorrectionLevel: 'H',
      margin: 1,
      width: 300,
      type: 'png',
      color: {
        dark: '#000000',
        light: '#ffffff'
      }
    };
    
    const encryptedData = this.encrypt(data);
    const qrOptions = { ...defaultOptions, ...options };
    
    // Generate QR code and save to file if path is provided
    if (options.outPath) {
      await qrcode.toFile(options.outPath, encryptedData, qrOptions);
      return options.outPath;
    }
    
    // Return QR code as data URL by default
    return await qrcode.toDataURL(encryptedData, qrOptions);
  }

  /**
   * Generate a secure QR code and return it as a Base64 encoded PNG
   * 
   * @param {string} data - The data to encode in the QR code
   * @param {Object} options - QR code options
   * @returns {Promise<string>} - Base64 encoded PNG image (data URL format)
   */
  async generateEncryptedQRBase64(data, options = {}) {
    const encryptedData = this.encrypt(data);
    const defaultOptions = {
      errorCorrectionLevel: 'H',
      margin: 1,
      width: 300,
      type: 'png'
    };
    
    const qrOptions = { ...defaultOptions, ...options };
    return await qrcode.toDataURL(encryptedData, qrOptions);
  }

  /**
   * Utility method to generate a random encryption key
   * 
   * @param {number} keySize - Size of the key in bits (128, 192, or 256)
   * @returns {string} Base64 encoded encryption key
   */
  static generateEncryptionKey(keySize = 256) {
    if (![128, 192, 256].includes(keySize)) {
      throw new Error('Key size must be 128, 192, or 256 bits');
    }
    
    const key = crypto.randomBytes(keySize / 8);
    return key.toString('base64');
  }
}

module.exports = SecureQR;