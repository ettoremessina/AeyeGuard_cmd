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
