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

    public async Task<long> FindUserCountWithSameUsername(
        string username,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);

        if (username.Length > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(username), "Username cannot exceed 100 characters.");
        }

        const string query = "SELECT COUNT(1) FROM Users WHERE Username = @Username";

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = new SqliteCommand(query, connection);
        command.Parameters.Add("@Username", SqliteType.Text).Value = username;

        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is long count
            ? count
            : throw new InvalidOperationException("The username count query returned an unexpected value.");
    }
}
