package com.remote;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Scanner;
import javax.crypto.SecretKey;

/**
 * SecureClient class provides secure remote access client functionality.
 * Based on ClientChat.java, this class will provide a user command prompt
 * and handle encrypted communication with the server.
 */
public class SecureClient {
    
    static int port = 6600;

    public static void main(String[] args) {
        TerminalUI.printClientBanner();
        
        try {
            // Connect to server
            InetAddress address = InetAddress.getByName("127.0.0.1");
            TerminalUI.showLoading("Establishing TCP connection...", 800);
            Socket socket = new Socket(address, port);
            TerminalUI.printSuccess("Connected to server at " + address + ":" + port);
            
            // Set socket timeout to 5 minutes to prevent indefinite hangs
            socket.setSoTimeout(1800000);
            
            try {
                // Initialize input/output streams
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                Scanner scannerInput = new Scanner(System.in);
                
                // === RSA-OAEP Key Exchange ===
                // Step 1: Receive server's RSA public key (or lockout message)
                String publicKeyString = in.readLine();
                
                // Check if the server has locked us out due to too many failed attempts
                if ("LOCKED_OUT".equals(publicKeyString)) {
                    TerminalUI.printError("\nAccess denied: Too many failed login attempts.");
                    TerminalUI.printWarning("Please try again later (30 second cooldown).");
                    scannerInput.close();
                    socket.close();
                    return;
                }
                
                PublicKey serverPublicKey = SecurityUtils.stringToPublicKey(publicKeyString);
                TerminalUI.printInfo("Server's RSA public key received.");
                
                // Step 2: Generate a fresh AES-256 session key (unique to this connection)
                TerminalUI.showLoading("Generating local AES-256 session key...", 1200);
                SecretKey secretKey = SecurityUtils.generateKey();
                
                // Step 3: Encrypt the AES key with server's RSA public key (OAEP) and send
                TerminalUI.showLoading("Encrypting session key via RSA-OAEP...", 600);
                String aesKeyString = SecurityUtils.keyToString(secretKey);
                String encryptedAesKey = SecurityUtils.encryptWithRSA(aesKeyString, serverPublicKey);
                out.println(encryptedAesKey);
                TerminalUI.printSuccess("AES-256 session key transmitted securely.");
                System.out.println();
                
                // Authentication handshake
                TerminalUI.printInfo("=== Authentication Required ===");
                TerminalUI.printPrompt("Enter Username: ");
                String username = scannerInput.nextLine();
                
                TerminalUI.printPrompt("Enter Password: ");
                // Now using the secure password reader
                String password = TerminalUI.readPassword();
                
                // Keep the prompt alignment nice
                System.out.println(); 
                
                TerminalUI.showLoading("Authenticating credentials...", 1000);
                
                // Encrypt and send credentials
                String encryptedUsername = SecurityUtils.encrypt(username, secretKey);
                String encryptedPassword = SecurityUtils.encrypt(password, secretKey);
                out.println(encryptedUsername);
                out.println(encryptedPassword);
                
                // Receive authentication response
                String encryptedAuthResponse = in.readLine();
                String authResponse = SecurityUtils.decrypt(encryptedAuthResponse, secretKey);
                
                if ("Unauthorized".equals(authResponse)) {
                    TerminalUI.printError("\nAuthentication Failed: Access Denied");
                    scannerInput.close();
                    socket.close();
                    return;
                }
                
                // Clear the screen for a clean shell experience after successful login
                TerminalUI.clearScreen();
                TerminalUI.printSuccess("Authentication Successful!\n");
                
                // Receive and decrypt welcome message
                String encryptedWelcome = in.readLine();
                String welcomeMessage = SecurityUtils.decrypt(encryptedWelcome, secretKey);
                System.out.println(TerminalUI.GREEN + "Server: " + welcomeMessage + TerminalUI.RESET);
                System.out.println();
                
                // Command input loop
                while (true) {
                    TerminalUI.printShellPrompt(username);
                    String command = scannerInput.nextLine();
                    
                    // Exit condition
                    if (command.equalsIgnoreCase("exit")) {
                        TerminalUI.printInfo("Disconnecting from server...");
                        break;
                    }
                    
                    // Encrypt and send command
                    String encryptedCommand = SecurityUtils.encrypt(command, secretKey);
                    out.println(encryptedCommand);
                    
                    // Receive and decrypt response
                    String encryptedResponse = in.readLine();
                    if (encryptedResponse != null) {
                        String response = SecurityUtils.decrypt(encryptedResponse, secretKey);
                        System.out.println(TerminalUI.CYAN + "\nServer Response:" + TerminalUI.RESET + "\n" + response + "\n");
                    } else {
                        TerminalUI.printWarning("Connection lost.");
                        break;
                    }
                }
                
                scannerInput.close();
                
            } finally {
                socket.close();
                TerminalUI.printInfo("Connection closed.");
            }
            
        } catch (IOException e) {
            TerminalUI.printError("Connection error: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            TerminalUI.printError("Client error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
