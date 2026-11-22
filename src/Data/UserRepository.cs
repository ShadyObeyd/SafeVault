using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Data;

public sealed class UserRepository(string connectionString)
{
    private readonly string _connectionString =
        !string.IsNullOrWhiteSpace(connectionString)
            ? connectionString
            : throw new ArgumentException("A connection string is required.", nameof(connectionString));

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                Id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                Username VARCHAR(100) NOT NULL CHECK (length(Username) <= 100),
                Email VARCHAR(100) NOT NULL CHECK (length(Email) <= 100)
            );
            """;

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<int> FindUserCountWithSameUsername(
        string username,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);

        if (username.Length > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(username), "Username cannot exceed 100 characters.");
        }

        string query = "SELECT COUNT(1) FROM Users WHERE Username = @Username";

        await using var connection = new SqliteConnection(_connectionString);
        using var command = new SqliteCommand(query, connection);

        command.Parameters.AddWithValue("@Username", username);

        await connection.OpenAsync(cancellationToken);

        int count = command.ExecuteScalar() as int? ?? 0;
        return count;
    }
}
