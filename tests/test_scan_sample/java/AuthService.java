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
