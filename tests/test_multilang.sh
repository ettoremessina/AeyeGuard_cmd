#!/bin/bash
# Test script for multi-language security analyzer

echo "Multi-Language Security Analyzer Test"
echo "======================================"
echo ""

# Create a test directory structure
TEST_DIR="test_scan_sample"
rm -rf "$TEST_DIR" 2>/dev/null
mkdir -p "$TEST_DIR/cs"
mkdir -p "$TEST_DIR/react"
mkdir -p "$TEST_DIR/java"

echo "Creating sample files..."

# Create a simple C# file with a vulnerability
cat > "$TEST_DIR/cs/UserController.cs" << 'EOF'
using System;

public class UserController
{
    public string GetUserById(string userId)
    {
        // SQL Injection vulnerability
        string query = "SELECT * FROM Users WHERE Id = " + userId;
        return ExecuteQuery(query);
    }

    private string ExecuteQuery(string query)
    {
        return "result";
    }
}
EOF

# Create a simple React TSX file with vulnerabilities
cat > "$TEST_DIR/react/Profile.tsx" << 'EOF'
import React from 'react';

interface User {
    name: string;
    bio: string;
}

// XSS vulnerability with dangerouslySetInnerHTML
export function UserProfile({ user }: { user: User }) {
    return (
        <div>
            <h1>{user.name}</h1>
            <div dangerouslySetInnerHTML={{ __html: user.bio }} />
        </div>
    );
}

// Hardcoded API key
const API_KEY = "sk-1234567890abcdef";

export function fetchData() {
    fetch('/api/data', {
        headers: { 'Authorization': API_KEY }
    });
}
EOF

# Create a simple Java file with vulnerabilities
cat > "$TEST_DIR/java/AuthService.java" << 'EOF'
import java.sql.*;
import java.io.*;

public class AuthService {
    // Hardcoded credentials
    private static final String DB_PASSWORD = "admin123";

    // SQL Injection vulnerability
    public boolean authenticate(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", DB_PASSWORD);
        String query = "SELECT * FROM users WHERE username = '" + username +
                       "' AND password = '" + password + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return rs.next();
    }

    // Insecure Deserialization
    public Object loadSession(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }

    // Command Injection
    public String ping(String host) throws IOException {
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("ping " + host);
        return "Ping executed";
    }
}
EOF

echo "✓ Sample files created in $TEST_DIR/"
echo ""
echo "Directory structure:"
find "$TEST_DIR" -type f
echo ""

# Run the scanner
echo "Running multi-language security scan..."
echo "========================================"
python3 ../AeyeGuard_cmd.py "$TEST_DIR" --max-files 10 --verbose

echo ""
echo "Test complete!"
echo ""
echo "To clean up: rm -rf $TEST_DIR"
