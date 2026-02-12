package com.remote;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * SecurityUtils class handles AES/RSA encryption logic for secure communication.
 * This class will provide encryption and decryption methods to ensure data confidentiality.
 */
public class SecurityUtils {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    
    /**
     * Generates a new AES SecretKey for encryption and decryption.
     * 
     * @return A newly generated SecretKey for AES encryption
     * @throws NoSuchAlgorithmException if AES algorithm is not available
     */
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128); // AES-128
        return keyGenerator.generateKey();
    }
    
    /**
     * Encrypts the given plaintext data using AES encryption.
     * 
     * @param data The plaintext string to encrypt
     * @param key The SecretKey to use for encryption
     * @return Base64 encoded encrypted string
     * @throws Exception if encryption fails
     */
    public static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    /**
     * Decrypts the given Base64 encoded encrypted data using AES decryption.
     * 
     * @param encryptedData The Base64 encoded encrypted string
     * @param key The SecretKey to use for decryption
     * @return The original plaintext string
     * @throws Exception if decryption fails
     */
    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }
    
}
