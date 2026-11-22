using Microsoft.Data.Sqlite;
using SafeVault.Models;
using SafeVault.Security;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

namespace SafeVault.Data;

public sealed class UserRepository(string connectionString)
{
    private const int BCryptWorkFactor = 12;
    private const int BCryptMaximumInputBytes = 72;
    private static readonly string DummyPasswordHash = BCrypt.Net.BCrypt.HashPassword(
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        workFactor: BCryptWorkFactor);

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
                Email VARCHAR(100) NOT NULL CHECK (length(Email) <= 100),
                PasswordHash TEXT NOT NULL DEFAULT '',
                Role TEXT NOT NULL DEFAULT 'User' CHECK (Role IN ('User', 'Admin'))
            );
            """;

        await command.ExecuteNonQueryAsync(cancellationToken);

        await EnsureColumnExistsAsync(connection, "PasswordHash", "TEXT NOT NULL DEFAULT ''", cancellationToken);
        await EnsureColumnExistsAsync(
            connection,
            "Role",
            "TEXT NOT NULL DEFAULT 'User' CHECK (Role IN ('User', 'Admin'))",
            cancellationToken);

        await using var indexCommand = connection.CreateCommand();
        indexCommand.CommandText =
            "CREATE UNIQUE INDEX IF NOT EXISTS UX_Users_Username ON Users(Username COLLATE NOCASE)";
        await indexCommand.ExecuteNonQueryAsync(cancellationToken);

        await using (var migrationsCommand = connection.CreateCommand())
        {
            migrationsCommand.CommandText = """
                CREATE TABLE IF NOT EXISTS SafeVaultMigrations (
                    MigrationId TEXT NOT NULL PRIMARY KEY
                )
                """;
            await migrationsCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        using var migrationTransaction = connection.BeginTransaction();
        await using var demoteAdminsCommand = connection.CreateCommand();
        demoteAdminsCommand.Transaction = migrationTransaction;
        demoteAdminsCommand.CommandText = """
            UPDATE Users
            SET Role = 'User'
            WHERE Role = 'Admin'
              AND NOT EXISTS (
                  SELECT 1
                  FROM SafeVaultMigrations
                  WHERE MigrationId = @MigrationId
              );

            INSERT OR IGNORE INTO SafeVaultMigrations (MigrationId)
            VALUES (@MigrationId);
            """;
        demoteAdminsCommand.Parameters.Add("@MigrationId", SqliteType.Text).Value =
            "DemoteExistingAdminsAfterPublicSignup";
        await demoteAdminsCommand.ExecuteNonQueryAsync(cancellationToken);
        await migrationTransaction.CommitAsync(cancellationToken);
    }

    public async Task<User?> AuthenticateAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        if (username.Length > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(username), "Username cannot exceed 100 characters.");
        }

        User? user = null;
        string? passwordHash = null;

        await using (var connection = new SqliteConnection(_connectionString))
        {
            await connection.OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT Id, Username, Email, PasswordHash, Role
                FROM Users
                WHERE Username = @Username COLLATE NOCASE
                LIMIT 1
                """;
            command.Parameters.Add("@Username", SqliteType.Text).Value = username;

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                user = new User(
                    reader.GetInt32(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.GetString(4));
                passwordHash = reader.GetString(3);
            }
        }

        if (user is null || string.IsNullOrEmpty(passwordHash) ||
            Encoding.UTF8.GetByteCount(password) > BCryptMaximumInputBytes)
        {
            BCrypt.Net.BCrypt.Verify(password, DummyPasswordHash);
            return null;
        }

        return BCrypt.Net.BCrypt.Verify(password, passwordHash) ? user : null;
    }

    public async Task<bool> CreateUserAsync(
        string username,
        string email,
        string password,
        string role,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        ArgumentException.ThrowIfNullOrWhiteSpace(role);

        if (!ValidationHelper.IsValidUsername(username))
        {
            throw new ArgumentException("Username is invalid.", nameof(username));
        }

        if (email.Length > 100 || !new EmailAddressAttribute().IsValid(email))
        {
            throw new ArgumentException("Email address is invalid.", nameof(email));
        }

        if (password.Length < 12 || Encoding.UTF8.GetByteCount(password) > BCryptMaximumInputBytes)
        {
            throw new ArgumentException("Password must be at least 12 characters and at most 72 UTF-8 bytes.", nameof(password));
        }

        if (role is not UserRoles.Admin and not UserRoles.User)
        {
            throw new ArgumentException("Role must be Admin or User.", nameof(role));
        }

        var passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: BCryptWorkFactor);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES (@Username, @Email, @PasswordHash, @Role)
            ON CONFLICT DO NOTHING
            """;
        command.Parameters.Add("@Username", SqliteType.Text).Value = username;
        command.Parameters.Add("@Email", SqliteType.Text).Value = email;
        command.Parameters.Add("@PasswordHash", SqliteType.Text).Value = passwordHash;
        command.Parameters.Add("@Role", SqliteType.Text).Value = role;
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
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

    private static async Task EnsureColumnExistsAsync(
        SqliteConnection connection,
        string columnName,
        string columnDefinition,
        CancellationToken cancellationToken)
    {
        var exists = false;
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "PRAGMA table_info(Users)";

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                if (reader.GetString(1).Equals(columnName, StringComparison.OrdinalIgnoreCase))
                {
                    exists = true;
                    break;
                }
            }
        }

        if (exists)
        {
            return;
        }

        await using var alterCommand = connection.CreateCommand();
        alterCommand.CommandText = $"ALTER TABLE Users ADD COLUMN {columnName} {columnDefinition}";
        await alterCommand.ExecuteNonQueryAsync(cancellationToken);
    }
}
