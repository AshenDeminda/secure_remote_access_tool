package com.remote;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import javax.crypto.SecretKey;

/**
 * SecureServer class provides secure remote access server functionality.
 * Based on Server.java, this class will use ProcessBuilder for command execution
 * and handle encrypted client connections.
 */
public class SecureServer {
    
    static int port = 6600;
    private static SecretKey secretKey;
    
    // Hardcoded authentication credentials
    private static final String ADMIN_USER = "admin";
    private static final String ADMIN_PASS = "secure123";

    public static void main(String[] args) {
        System.out.println("\t\t Secure Remote Access Server");
        System.out.println("\t\t===========================\n\n");
        
        try {
            // Generate encryption key
            secretKey = SecurityUtils.generateKey();
            System.out.println("Encryption key generated successfully.");
            
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server started on port " + port);
            
            try {
                while (true) {
                    Socket socket = serverSocket.accept();
                    System.out.println("Client connected: " + socket.getInetAddress());
                    
                    // Handle each client in a separate thread
                    Thread clientThread = new Thread(new ClientHandler(socket, secretKey));
                    clientThread.start();
                }
            } finally {
                serverSocket.close();
            }
        } catch (Exception e) {
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * ClientHandler class handles individual client connections in separate threads.
     */
    static class ClientHandler implements Runnable {
        private Socket socket;
        private SecretKey key;
        
        public ClientHandler(Socket socket, SecretKey key) {
            this.socket = socket;
            this.key = key;
        }
        
        @Override
        public void run() {
            try {
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                
                // Send encryption key to client (Base64 encoded)
                String keyString = SecurityUtils.keyToString(key);
                out.println(keyString);
                
                // Authentication handshake
                try {
                    // Receive encrypted username and password
                    String encryptedUsername = in.readLine();
                    String encryptedPassword = in.readLine();
                    
                    if (encryptedUsername == null || encryptedPassword == null) {
                        socket.close();
                        return;
                    }
                    
                    // Decrypt credentials
                    String username = SecurityUtils.decrypt(encryptedUsername, key);
                    String password = SecurityUtils.decrypt(encryptedPassword, key);
                    
                    // Verify credentials
                    if (!ADMIN_USER.equals(username) || !ADMIN_PASS.equals(password)) {
                        System.out.println("Authentication failed for user: " + username);
                        String unauthorizedMsg = SecurityUtils.encrypt("Unauthorized", key);
                        out.println(unauthorizedMsg);
                        socket.close();
                        return;
                    }
                    
                    System.out.println("User authenticated: " + username);
                    
                    // Send authentication success message
                    String authSuccessMsg = SecurityUtils.encrypt("Authenticated", key);
                    out.println(authSuccessMsg);
                    
                } catch (Exception e) {
                    System.err.println("Authentication error: " + e.getMessage());
                    socket.close();
                    return;
                }
                
                // Send welcome message (encrypted)
                try {
                    String welcomeMsg = SecurityUtils.encrypt(
                        "Welcome to Secure Remote Access Server", key);
                    out.println(welcomeMsg);
                } catch (Exception e) {
                    System.err.println("Error sending welcome message: " + e.getMessage());
                    socket.close();
                    return;
                }
                
                // Process client commands
                String encryptedCommand;
                while ((encryptedCommand = in.readLine()) != null) {
                    try {
                        // Decrypt the incoming command
                        String command = SecurityUtils.decrypt(encryptedCommand, key);
                        System.out.println("Received command: " + command);
                        
                        // Execute command using ProcessBuilder
                        String result = executeCommand(command);
                        
                        // Encrypt and send response
                        String encryptedResult = SecurityUtils.encrypt(result, key);
                        out.println(encryptedResult);
                        
                    } catch (Exception e) {
                        try {
                            String errorMsg = "Error processing command: " + e.getMessage();
                            String encryptedError = SecurityUtils.encrypt(errorMsg, key);
                            out.println(encryptedError);
                        } catch (Exception encryptException) {
                            System.err.println("Error encrypting error message: " + encryptException.getMessage());
                        }
                    }
                }
                
            } catch (IOException e) {
                System.err.println("Client handler error: " + e.getMessage());
            } finally {
                try {
                    socket.close();
                    System.out.println("Client disconnected.");
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        
        /**
         * Executes a system command using ProcessBuilder.
         * 
         * @param command The command string to execute
         * @return The output of the command execution
         */
        private String executeCommand(String command) {
            StringBuilder output = new StringBuilder();
            
            try {
                // Parse command for ProcessBuilder (split by spaces)
                String[] cmdArray = command.split("\\s+");
                ProcessBuilder processBuilder = new ProcessBuilder(cmdArray);
                processBuilder.redirectErrorStream(true);
                
                Process process = processBuilder.start();
                
                // Read command output
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                
                int exitCode = process.waitFor();
                output.append("Exit Code: ").append(exitCode);
                
            } catch (Exception e) {
                output.append("Command execution failed: ").append(e.getMessage());
            }
            
            return output.toString();
        }
    }
}
