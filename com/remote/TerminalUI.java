package com.remote;

/**
 * Terminal UI helper class providing ANSI escape codes for styling console output,
 * ASCII art banners, and standardized formatted logging methods.
 */
public class TerminalUI {

    // ANSI Color Constants
    public static final String RESET = "\033[0m";
    public static final String BOLD = "\033[1m";
    public static final String RED = "\033[0;31m";
    public static final String GREEN = "\033[0;32m";
    public static final String YELLOW = "\033[0;33m";
    public static final String BLUE = "\033[0;34m";
    public static final String CYAN = "\033[0;36m";

    // ASCII Banners
    public static final String SERVER_BANNER = 
        CYAN + BOLD + "\n" +
        "  ____                            _    ____                        \n" +
        " / ___|  ___  ___ _   _ _ __ ___ | |_ / ___|  ___ _ ____   ___ ___ \n" +
        " \\___ \\ / _ \\/ __| | | | '__/ _ \\| __|\\___ \\ / _ \\ '__\\ \\ / / _ \\ '__|\n" +
        "  ___) |  __/ (__| |_| | | |  __/| |_  ___) |  __/ |   \\ V /  __/ |   \n" +
        " |____/ \\___|\\___|\\__,_|_|  \\___| \\__||____/ \\___|_|    \\_/ \\___|_|   \n" + RESET;

    public static final String CLIENT_BANNER = 
        CYAN + BOLD + "\n" +
        "  ____                            _    ____ _ _            _   \n" +
        " / ___|  ___  ___ _   _ _ __ ___ | |_ / ___| (_) ___ _ __ | |_ \n" +
        " \\___ \\ / _ \\/ __| | | | '__/ _ \\| __| |   | | |/ _ \\ '_ \\| __|\n" +
        "  ___) |  __/ (__| |_| | | |  __/| |_| |___| | |  __/ | | | |_ \n" +
        " |____/ \\___|\\___|\\__,_|_|  \\___| \\__|\\____|_|_|\\___|_| |_|\\__|\n" + RESET;

    public static final String SEPARATOR = YELLOW + "==============================================================" + RESET;

    // Helper Methods for Clean Logging ---
    
    public static void clearScreen() {
        System.out.print("\033[H\033[2J");
        System.out.flush();
    }

    public static void printServerBanner() {
        clearScreen();
        System.out.println(SERVER_BANNER);
        System.out.println(SEPARATOR + "\n");
    }

    public static void printClientBanner() {
        clearScreen();
        System.out.println(CLIENT_BANNER);
        System.out.println(SEPARATOR + "\n");
    }

    // Success (Green)
    public static void printSuccess(String message) {
        System.out.println(GREEN + "[+] " + RESET + message);
    }

    // Info Logging (Timestamped for Server)
    public static void printLog(String category, String message) {
        String time = new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date());
        System.out.println(YELLOW + "[" + time + "] " + CYAN + "[" + category + "] " + RESET + message);
    }
    
    // Status (Blue)
    public static void printInfo(String message) {
        System.out.println(BLUE + "[*] " + RESET + message);
    }

    // Warnings (Yellow)
    public static void printWarning(String message) {
        System.out.println(YELLOW + "[!] " + RESET + message);
    }

    // Errors (Red)
    public static void printError(String message) {
        System.out.println(RED + "[-] ERROR: " + RESET + message);
    }

    // Dynamic shell prompt formatting
    public static void printShellPrompt(String username) {
        System.out.print(GREEN + BOLD + username + "@remote-server" + RESET + ":" + BLUE + BOLD + "~$ " + RESET);
    }
    
    // Simple prompt formatting
    public static void printPrompt(String message) {
        System.out.print(CYAN + BOLD + message + RESET + " ");
    }

    // Geeky Loading Animation
    public static void showLoading(String message, int durationMs) {
        System.out.print(BLUE + "[*] " + RESET + message + " ");
        String[] spinner = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
        int iterations = durationMs / 100;
        for (int i = 0; i < iterations; i++) {
            System.out.print("\b" + YELLOW + spinner[i % spinner.length] + RESET);
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        System.out.print("\b" + GREEN + "✓" + RESET + "\n");
    }

    // Read password securely
    public static String readPassword() {
        java.io.Console console = System.console();
        if (console != null) {
            char[] passwordArray = console.readPassword();
            return passwordArray != null ? new String(passwordArray) : "";
        } else {
            // Fallback if not running in a true terminal (e.g. IDE)
            // Note: Does not mask in some IDE environments.
            return new java.util.Scanner(System.in).nextLine();
        }
    }
}
