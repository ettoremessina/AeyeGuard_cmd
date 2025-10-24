using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Security.Cryptography;

namespace VulnerableApp
{
    public class UserController
    {
        private string connectionString = "Server=localhost;Database=MyDB;User Id=sa;Password=hardcoded123;";

        // SQL Injection vulnerability
        public void GetUserById(string userId)
        {
            string query = "SELECT * FROM Users WHERE Id = " + userId;

            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                SqlCommand cmd = new SqlCommand(query, conn);
                conn.Open();
                var reader = cmd.ExecuteReader();
            }
        }

        // Command Injection vulnerability
        public void BackupDatabase(string filename)
        {
            Process.Start("cmd.exe", "/c backup.bat " + filename);
        }

        // Weak cryptography
        public string EncryptPassword(string password)
        {
            MD5 md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(hash);
        }

        // Path traversal vulnerability
        public string ReadFile(string filename)
        {
            return System.IO.File.ReadAllText("uploads/" + filename);
        }

        // Missing authentication check
        public void DeleteUser(int userId)
        {
            // No authorization check before deletion
            string query = $"DELETE FROM Users WHERE Id = {userId}";
            ExecuteQuery(query);
        }

        // Sensitive data in logs
        public void LogUserCredentials(string username, string password)
        {
            Console.WriteLine($"Login attempt: {username} / {password}");
        }

        // Insecure random number generation
        public string GenerateSessionToken()
        {
            Random rand = new Random();
            return rand.Next().ToString();
        }

        private void ExecuteQuery(string query)
        {
            // Implementation
        }
    }
}
