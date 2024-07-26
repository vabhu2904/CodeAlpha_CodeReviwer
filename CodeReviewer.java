import java.util.*;
import java.io.File;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * CodeReviewer is a Java application that checks code files for security vulnerabilities
 * and provides recommendations to tackle the security issues using static analysis tools.
 * This application supports Java, Python, C, C++, and JavaScript.
 */
public class CodeReviewer {
    public static void main(String[] args) {
        // Ensure that the correct number of arguments are provided
        if (args.length != 2) {
            System.out.println("Usage: java CodeReviewer <language> <file_path>");
            return;
        }
        String language = args[0];
        String filePath = args[1];
        File file = new File(filePath);

        // Check if the given file path is valid or not
        if (!file.exists() || !file.isFile()) {
            System.out.println("INVALID File Path: Given file path does not exist!");
            return;
        }

        // Analyze the code based on the provided language
        try {
            switch (language.toLowerCase()) {
                case "java":
                    checkCode_Java(filePath);
                    break;
                case "python":
                    checkCode_Python(filePath);
                    break;
                case "c":
                case "cpp":
                case "c++":
                    checkCode_C_Cpp(filePath);
                    break;
                case "javascript":
                    checkCode_JS(filePath);
                    break;
                default:
                    System.out.println("Unsupported Language: " + language);
                    break;
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Check Java code for security vulnerabilities using SpotBugs.
     * @param filePath - the path to the Java file.
     */
    private static void checkCode_Java(String filePath) throws IOException, InterruptedException {
        System.out.println("Scanning Java code for any security vulnerabilities...");
        String[] command = {"spotbugs", "-textui", filePath};
        executeCmd(command);
    }

    /**
     * Check Python code for security vulnerabilities using Bandit.
     * @param filePath - the path to the Python file.
     */
    private static void checkCode_Python(String filePath) throws IOException, InterruptedException {
        System.out.println("Scanning Python code for any security vulnerabilities...");
        String[] command = {"bandit", "-r", filePath};
        executeCmd(command);
    }

    /**
     * Check C/C++ code for security vulnerabilities using Cppcheck.
     * @param filePath - the path to the C/C++ file.
     */
    private static void checkCode_C_Cpp(String filePath) throws IOException, InterruptedException {
        System.out.println("Scanning C/C++ code for any security vulnerabilities...");
        String[] command = {"cppcheck", "--enable=all", filePath};
        executeCmd(command);
    }

    /**
     * Check JavaScript code for security vulnerabilities using ESLint.
     * @param filePath - the path to the JavaScript file.
     */
    private static void checkCode_JS(String filePath) throws IOException, InterruptedException {
        System.out.println("Scanning JavaScript code for any security vulnerabilities...");
        String[] command = {"eslint", filePath};
        executeCmd(command);
    }

    /**
     * Execute system command and process its output.
     * @param command - command to execute.
     * @throws IOException, InterruptedException
     */
    private static void executeCmd(String[] command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command).start();

        // Read output of the command
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }

        // Wait for the process to complete
        process.waitFor();

        // Print output to the console
        System.out.println(output.toString());

        // Provide appropriate recommendations based on the tool's output
        reviewRecmd(output.toString());
    }

    /**
     * Provide recommendations for secure coding practices based on tool's output and analysis.
     * @param output - contains output of the static tool analysis.
     */
    private static void reviewRecmd(String output) {
        // Return recommendations and reviews based on identified vulnerabilities in output

        if (output.contains("SQL Injection")) {
            System.out.println("Recommendation: Use parameterized queries to prevent SQL Injection.");
        }
        if (output.contains("XSS")) {
            System.out.println("Recommendation: Sanitize user inputs to prevent Cross-Site Scripting (XSS).");
        }
        if (output.contains("Command Injection")) {
            System.out.println("Recommendation: Validate and sanitize user inputs to prevent Command Injection.");
        }
        if (output.contains("Path Traversal")) {
            System.out.println("Recommendation: Validate file paths and restrict file access to prevent Path Traversal.");
        }
        if (output.contains("CSRF")) {
            System.out.println("Recommendation: Implement CSRF protection to prevent Cross-Site Request Forgery (CSRF).");
        }
        if (output.contains("Buffer Overflow")) {
            System.out.println("Recommendation: Use safe functions and perform bounds checking to prevent Buffer Overflow.");
        }
        if (output.contains("Insecure Transport")) {
            System.out.println("Recommendation: Use TLS/SSL to encrypt data in transit and avoid using insecure protocols.");
        }
        if (output.contains("Weak Cryptography")) {
            System.out.println("Recommendation: Use strong, industry-standard cryptographic algorithms and libraries.");
        }
        if (output.contains("Unvalidated Redirects and Forwards")) {
            System.out.println("Recommendation: Validate URLs and use safe methods to handle redirects and forwards.");
        }
        if (output.contains("Security Misconfiguration")) {
            System.out.println("Recommendation: Ensure secure configuration for servers, databases, and application frameworks.");
        }
        if (output.contains("Sensitive Data Exposure")) {
            System.out.println("Recommendation: Encrypt sensitive data at rest and in transit, and use secure storage mechanisms.");
        }
        if (output.contains("Improper Access Control")) {
            System.out.println("Recommendation: Implement proper authentication and authorization checks to prevent unauthorized access.");
        }

        // General recommendations
        System.out.println("General Recommendations:");
        System.out.println("- Keep dependencies up to date to avoid known vulnerabilities.");
        System.out.println("- Implement proper error handling to avoid leaking sensitive information.");
        System.out.println("- Regularly perform security testing and code reviews.");
    }
}
