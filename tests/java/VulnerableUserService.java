import java.io.*;
import java.sql.*;
import javax.naming.*;
import java.lang.reflect.*;

/**
 * Example vulnerable Java class for testing AeyeGuard_java analyzer.
 * Contains multiple Java-specific security vulnerabilities.
 */
public class VulnerableUserService {

    // Hardcoded credentials (CWE-798)
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk-1234567890abcdef";

    private Connection dbConnection;

    // SQL Injection vulnerability (CWE-89)
    public User getUserById(String userId) throws SQLException {
        // Vulnerable: concatenating user input directly into SQL query
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = dbConnection.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        if (rs.next()) {
            return new User(rs.getString("name"), rs.getString("email"));
        }
        return null;
    }

    // Insecure Deserialization vulnerability (CWE-502)
    public Object loadUserData(InputStream input) throws Exception {
        // Vulnerable: deserializing untrusted data
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();  // Can execute arbitrary code
    }

    // Reflection Abuse vulnerability (CWE-470)
    public Object createInstance(String className) throws Exception {
        // Vulnerable: loading arbitrary classes from user input
        Class<?> clazz = Class.forName(className);
        return clazz.newInstance();  // Deprecated and unsafe
    }

    // JNDI Injection vulnerability (CWE-917)
    public Object lookupResource(String jndiName) throws NamingException {
        // Vulnerable: JNDI lookup with user-controlled name (Log4Shell pattern)
        Context ctx = new InitialContext();
        return ctx.lookup(jndiName);  // Can load remote classes
    }

    // Command Injection vulnerability (CWE-78)
    public String executeCommand(String userInput) throws IOException {
        // Vulnerable: executing shell commands with user input
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("ping " + userInput);

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // Path Traversal vulnerability (CWE-22)
    public String readFile(String fileName) throws IOException {
        // Vulnerable: reading files with user-controlled path
        File file = new File("/var/data/" + fileName);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        reader.close();
        return content.toString();
    }

    // Weak Cryptography (CWE-327)
    public String hashPassword(String password) throws Exception {
        // Vulnerable: using weak MD5 algorithm
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return bytesToHex(hash);
    }

    // Reflection with setAccessible (CWE-470)
    public void modifyPrivateField(Object obj, String fieldName, Object value) throws Exception {
        // Vulnerable: bypassing access controls
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);  // Breaking encapsulation
        field.set(obj, value);
    }

    // XXE (XML External Entity) vulnerability (CWE-611)
    public void parseXml(String xmlData) throws Exception {
        // Vulnerable: parsing XML without disabling external entities
        javax.xml.parsers.DocumentBuilderFactory factory =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        // Missing: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
    }

    // Helper method
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    // Simple User class
    static class User implements Serializable {
        private String name;
        private String email;

        public User(String name, String email) {
            this.name = name;
            this.email = email;
        }

        public String getName() { return name; }
        public String getEmail() { return email; }
    }
}
