package com.remote;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
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
        System.out.println("\t\t Secure Remote Access Client");
        System.out.println("\t\t===========================\n\n");
        
        try {
            // Generate encryption key (must match server's key in production)
            SecretKey secretKey = SecurityUtils.generateKey();
            System.out.println("Encryption key generated successfully.");
            
            // Connect to server
            InetAddress address = InetAddress.getByName("127.0.0.1");
            Socket socket = new Socket(address, port);
            System.out.println("Connected to server at " + address + ":" + port);
            
            try {
                // Initialize input/output streams
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                Scanner scannerInput = new Scanner(System.in);
                
                // Authentication handshake
                System.out.println("=== Authentication Required ===");
                System.out.print("Enter Username: ");
                String username = scannerInput.nextLine();
                
                System.out.print("Enter Password: ");
                String password = scannerInput.nextLine();
                
                // Encrypt and send credentials
                String encryptedUsername = SecurityUtils.encrypt(username, secretKey);
                String encryptedPassword = SecurityUtils.encrypt(password, secretKey);
                out.println(encryptedUsername);
                out.println(encryptedPassword);
                
                // Receive authentication response
                String encryptedAuthResponse = in.readLine();
                String authResponse = SecurityUtils.decrypt(encryptedAuthResponse, secretKey);
                
                if ("Unauthorized".equals(authResponse)) {
                    System.out.println("\nAuthentication Failed: Access Denied");
                    scannerInput.close();
                    socket.close();
                    return;
                }
                
                System.out.println("Authentication Successful!\n");
                
                // Receive and decrypt welcome message
                String encryptedWelcome = in.readLine();
                String welcomeMessage = SecurityUtils.decrypt(encryptedWelcome, secretKey);
                System.out.println("Server: " + welcomeMessage);
                System.out.println();
                
                // Command input loop
                while (true) {
                    System.out.print("Enter command (or 'exit' to quit): ");
                    String command = scannerInput.nextLine();
                    
                    // Exit condition
                    if (command.equalsIgnoreCase("exit")) {
                        System.out.println("Disconnecting from server...");
                        break;
                    }
                    
                    // Encrypt and send command
                    String encryptedCommand = SecurityUtils.encrypt(command, secretKey);
                    out.println(encryptedCommand);
                    
                    // Receive and decrypt response
                    String encryptedResponse = in.readLine();
                    if (encryptedResponse != null) {
                        String response = SecurityUtils.decrypt(encryptedResponse, secretKey);
                        System.out.println("\nServer Response:");
                        System.out.println(response);
                        System.out.println();
                    } else {
                        System.out.println("Connection lost.");
                        break;
                    }
                }
                
                scannerInput.close();
                
            } finally {
                socket.close();
                System.out.println("Connection closed.");
            }
            
        } catch (IOException e) {
            System.err.println("Connection error: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
