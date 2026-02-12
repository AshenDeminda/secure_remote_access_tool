# Secure Remote Access Tool

A secure telnet alternative built with Java that enables encrypted remote command execution over TCP/IP networks. This tool demonstrates network programming, multi-threading, and cryptography concepts using AES encryption.

## Features

- 🔐 **AES Encryption**: All commands and responses are encrypted using AES/ECB/PKCS5Padding
- 🔑 **Authentication**: Secure username/password authentication before access
- 🚀 **Multi-threaded Server**: Handles multiple client connections simultaneously
- 💻 **Remote Command Execution**: Execute system commands remotely using ProcessBuilder
- 🌐 **Network Communication**: Built on Java Socket programming

## Project Structure

```
SecureRemoteAccess/
├── README.md
└── com/
    └── remote/
        ├── SecurityUtils.java    # AES encryption/decryption utilities
        ├── SecureServer.java     # Multi-threaded server implementation
        └── SecureClient.java     # Interactive client application
```

## Prerequisites

- Java Development Kit (JDK) 8 or higher
- Basic understanding of terminal/command prompt

## Compilation

Navigate to the project root directory and compile all Java files:

```bash
javac com/remote/SecurityUtils.java com/remote/SecureServer.java com/remote/SecureClient.java
```

This will generate `.class` files in the same directory structure.

## Running the Application

### Step 1: Start the Server

Open a terminal/command prompt and run:

```bash
java com.remote.SecureServer
```

You should see:
```
		 Secure Remote Access Server
		===========================


Encryption key generated successfully.
Server started on port 6600
```

The server is now listening for client connections on port 6600.

### Step 2: Start the Client

Open a **new** terminal/command prompt and run:

```bash
java com.remote.SecureClient
```

### Step 3: Authenticate

When prompted, enter the credentials:

```
Enter Username: admin
Enter Password: secure123
```

**Default Credentials:**
- Username: `admin`
- Password: `secure123`

*(You can modify these in the `SecureServer.java` file)*

### Step 4: Execute Commands

Once authenticated, you can enter system commands:

```
Enter command (or 'exit' to quit): dir
```

or on Linux/Mac:

```
Enter command (or 'exit' to quit): ls -la
```

The server will execute the command and return the encrypted output, which the client will decrypt and display.

## Example Session

**Server Terminal:**
```
		 Secure Remote Access Server
		===========================

Encryption key generated successfully.
Server started on port 6600
Client connected: /127.0.0.1
User authenticated: admin
Received command: dir
```

**Client Terminal:**
```
		 Secure Remote Access Client
		===========================

Encryption key generated successfully.
Connected to server at 127.0.0.1:6600
=== Authentication Required ===
Enter Username: admin
Enter Password: secure123
Authentication Successful!

Server: Welcome to Secure Remote Access Server

Enter command (or 'exit' to quit): dir
Server Response:
[directory listing output...]
Exit Code: 0

Enter command (or 'exit' to quit): exit
Disconnecting from server...
Connection closed.
```

## Security Notes

⚠️ **WARNING: This is an educational project!**

- **Not for production use**: This tool demonstrates concepts but lacks enterprise-grade security features
- **Shared encryption key**: In this implementation, both client and server generate separate keys (this is a demonstration limitation - in production, use proper key exchange protocols like Diffie-Hellman)
- **Hardcoded credentials**: Change the default username/password in `SecureServer.java` before use
- **ECB mode**: Using ECB mode for demonstration; production systems should use CBC or GCM modes
- **No input validation**: Commands are executed without sanitization - use responsibly

## How It Works

1. **Server Startup**: Generates an AES encryption key and listens on port 6600
2. **Client Connection**: Client connects and generates its own AES key
3. **Authentication**: Client sends encrypted username/password; server validates
4. **Command Loop**: 
   - Client encrypts command → sends to server
   - Server decrypts → executes via ProcessBuilder → captures output
   - Server encrypts output → sends to client
   - Client decrypts → displays to user
5. **Multi-threading**: Each client runs in a separate thread for concurrent access

## Customization

### Change Server Port

Edit `SecureServer.java` and `SecureClient.java`:
```java
static int port = 6600;  // Change to your preferred port
```

### Change Authentication Credentials

Edit `SecureServer.java`:
```java
private static final String ADMIN_USER = "admin";  // Your username
private static final String ADMIN_PASS = "secure123";  // Your password
```

### Change Server Address

Edit `SecureClient.java`:
```java
InetAddress address = InetAddress.getByName("127.0.0.1");  // Change to server IP
```

## Troubleshooting

**Connection Refused:**
- Ensure the server is running before starting the client
- Check that port 6600 is not blocked by firewall
- Verify the IP address in client matches the server's address

**Authentication Failed:**
- Verify username and password match the hardcoded credentials
- Check for typos (case-sensitive)

**Command Execution Failed:**
- Some commands require specific syntax (e.g., Windows: `dir`, Linux: `ls`)
- Commands with pipes or redirects may not work as expected
- Avoid interactive commands (they won't work in ProcessBuilder context)

## Learning Objectives

This project demonstrates:
- Java networking with ServerSocket and Socket
- Multi-threaded server architecture
- Symmetric encryption with AES
- Process execution with ProcessBuilder
- Input/output streams and buffering
- Base64 encoding for encrypted data transmission

## License

This is an educational project. Feel free to use and modify for learning purposes.

## Contributing

This is a learning project, but suggestions and improvements are welcome!

---

**Happy Secure Coding! 🔒**