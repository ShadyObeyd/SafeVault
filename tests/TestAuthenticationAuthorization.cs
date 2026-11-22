using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Security;

[TestFixture]
public class TestAuthenticationAuthorization
{
    private const string Password = "CorrectHorseBattery!42";
    private string _databasePath = null!;

    [SetUp]
    public async Task SetUp()
    {
        _databasePath = Path.Combine(Path.GetTempPath(), $"SafeVault.AuthTests.{Guid.NewGuid():N}.db");
        var repository = new UserRepository(CreateConnectionString(_databasePath));
        await repository.InitializeAsync();
        await repository.CreateUserAsync("admin", "admin@example.com", Password);
        await repository.CreateUserAsync("alice", "alice@example.com", Password);
    }

    [TearDown]
    public void TearDown()
    {
        DeleteDatabaseFiles(_databasePath);
    }

    [Test]
    public async Task Repository_AuthenticatesProvisionedPassword()
    {
        var repository = new UserRepository(CreateConnectionString(_databasePath));
        var user = await repository.AuthenticateAsync("alice", Password);

        Assert.That(user?.Username, Is.EqualTo("alice"));
        Assert.That(user?.Role, Is.EqualTo(UserRoles.User));
    }

    [Test]
    public async Task FirstCreatedUserIsAdminAndLaterUsersAreUsers()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"SafeVault.BootstrapTests.{Guid.NewGuid():N}.db");
        try
        {
            var repository = new UserRepository(CreateConnectionString(databasePath));
            await repository.InitializeAsync();
            await repository.CreateUserAsync("first", "first@example.com", Password);
            await repository.CreateUserAsync("second", "second@example.com", Password);

            var firstUser = await repository.AuthenticateAsync("first", Password);
            var secondUser = await repository.AuthenticateAsync("second", Password);

            Assert.That(firstUser?.Role, Is.EqualTo(UserRoles.Admin));
            Assert.That(secondUser?.Role, Is.EqualTo(UserRoles.User));
        }
        finally
        {
            DeleteDatabaseFiles(databasePath);
        }
    }

    [Test]
    public async Task InitializePromotesOldestExistingUserWhenNoAdminExists()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"SafeVault.MigrationTests.{Guid.NewGuid():N}.db");
        try
        {
            await using (var connection = new SqliteConnection(CreateConnectionString(databasePath)))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE Users (
                        Id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                        Username VARCHAR(100) NOT NULL,
                        Email VARCHAR(100) NOT NULL,
                        PasswordHash TEXT NOT NULL DEFAULT ''
                    );
                    INSERT INTO Users (Username, Email, PasswordHash)
                    VALUES ('oldest', 'oldest@example.com', 'legacy-hash'),
                           ('newer', 'newer@example.com', 'legacy-hash');
                    """;
                await command.ExecuteNonQueryAsync();
            }

            var repository = new UserRepository(CreateConnectionString(databasePath));
            await repository.InitializeAsync();
            await using var verifyConnection = new SqliteConnection(CreateConnectionString(databasePath));
            await verifyConnection.OpenAsync();
            await using var verifyCommand = verifyConnection.CreateCommand();
            verifyCommand.CommandText = "SELECT Role FROM Users WHERE Username = 'oldest'";

            Assert.That(await verifyCommand.ExecuteScalarAsync(), Is.EqualTo(UserRoles.Admin));
        }
        finally
        {
            DeleteDatabaseFiles(databasePath);
        }
    }

    [Test]
    public async Task Registration_FirstAccountCanBeAdminWhenOnlyLegacyPasswordlessUsersExist()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"SafeVault.LegacyRegistrationTests.{Guid.NewGuid():N}.db");
        try
        {
            await using (var connection = new SqliteConnection(CreateConnectionString(databasePath)))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE Users (
                        Id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                        Username VARCHAR(100) NOT NULL,
                        Email VARCHAR(100) NOT NULL
                    );
                    INSERT INTO Users (Username, Email)
                    VALUES ('legacy', 'legacy@example.com');
                    """;
                await command.ExecuteNonQueryAsync();
            }

            var repository = new UserRepository(CreateConnectionString(databasePath));
            await repository.InitializeAsync();
            await repository.CreateUserAsync("first", "first@example.com", Password);
            var newUser = await repository.AuthenticateAsync("first", Password);

            Assert.That(newUser?.Role, Is.EqualTo(UserRoles.Admin));
            Assert.That(await repository.AuthenticateAsync("legacy", Password), Is.Null);
        }
        finally
        {
            DeleteDatabaseFiles(databasePath);
        }
    }

    [Test]
    public async Task Registration_FirstAccountIsAdminAndLaterAccountsAreUsers()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"SafeVault.RegistrationTests.{Guid.NewGuid():N}.db");
        try
        {
            using var factory = CreateFactory(databasePath);
            using var client = CreateClient(factory);

            using var firstResponse = await RegisterAsync(client, "first", "first@example.com");
            using var secondResponse = await RegisterAsync(client, "second", "second@example.com");

            Assert.That(firstResponse.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(firstResponse.Headers.Location?.OriginalString, Is.EqualTo("/Users/Login"));
            Assert.That(secondResponse.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));

            var repository = factory.Services.GetRequiredService<UserRepository>();
            var firstUser = await repository.AuthenticateAsync("first", Password);
            var secondUser = await repository.AuthenticateAsync("second", Password);
            Assert.That(firstUser?.Role, Is.EqualTo(UserRoles.Admin));
            Assert.That(secondUser?.Role, Is.EqualTo(UserRoles.User));

            using var loginResponse = await LoginAsync(client, "first");
            using var adminResponse = await client.GetAsync("/Admin/Dashboard");
            Assert.That(loginResponse.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(adminResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }
        finally
        {
            DeleteDatabaseFiles(databasePath);
        }
    }

    [Test]
    public async Task Registration_RejectsCaseInsensitiveDuplicateUsername()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"SafeVault.DuplicateRegistrationTests.{Guid.NewGuid():N}.db");
        try
        {
            using var factory = CreateFactory(databasePath);
            using var client = CreateClient(factory);
            using var firstResponse = await RegisterAsync(client, "first", "first@example.com");
            var token = await GetRequestVerificationTokenAsync(client, "/Users/Register");
            using var duplicateResponse = await PostRegistrationAsync(
                client,
                token,
                "FIRST",
                "other@example.com",
                "DifferentPassword!42");
            var body = await duplicateResponse.Content.ReadAsStringAsync();

            Assert.That(firstResponse.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(duplicateResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(body, Does.Contain("That username is already in use."));

            var repository = factory.Services.GetRequiredService<UserRepository>();
            Assert.That(await repository.AuthenticateAsync("first", Password), Is.Not.Null);
            Assert.That(await repository.AuthenticateAsync("FIRST", "DifferentPassword!42"), Is.Null);
        }
        finally
        {
            DeleteDatabaseFiles(databasePath);
        }
    }

    [Test]
    public async Task Login_RejectsInvalidPasswordWithoutAuthenticating()
    {
        using var factory = CreateFactory(_databasePath);
        using var client = CreateClient(factory);
        var token = await GetRequestVerificationTokenAsync(client);
        using var response = await PostLoginAsync(client, token, "alice", "incorrect-password");
        var body = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(body, Does.Contain("Invalid username or password."));

        using var adminResponse = await client.GetAsync("/Admin/Dashboard");
        Assert.That(adminResponse.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(adminResponse.Headers.Location?.AbsolutePath, Is.EqualTo("/Users/Login"));
    }

    [Test]
    public async Task UserRole_CannotAccessAdminDashboard()
    {
        using var factory = CreateFactory(_databasePath);
        using var client = CreateClient(factory);
        using var loginResponse = await LoginAsync(client, "alice");

        Assert.That(loginResponse.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(loginResponse.Headers.Location?.OriginalString, Is.EqualTo("/Users/LoggedIn"));

        using var response = await client.GetAsync("/Admin/Dashboard");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location?.AbsolutePath, Is.EqualTo("/Users/AccessDenied"));
    }

    [Test]
    public async Task AdminRole_CanAccessAdminDashboard()
    {
        using var factory = CreateFactory(_databasePath);
        var repository = factory.Services.GetRequiredService<UserRepository>();
        var authenticatedUser = await repository.AuthenticateAsync("admin", Password);
        Assert.That(authenticatedUser?.Role, Is.EqualTo(UserRoles.Admin));

        using var client = CreateClient(factory);
        using var loginResponse = await LoginAsync(client, "admin");
        using var response = await client.GetAsync("/Admin/Dashboard");
        var body = await response.Content.ReadAsStringAsync();
        var loginBody = await loginResponse.Content.ReadAsStringAsync();

        Assert.That(loginResponse.StatusCode, Is.EqualTo(HttpStatusCode.Redirect), loginBody);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(body, Does.Contain("Administrative access confirmed."));
    }

    [Test]
    public async Task Login_IgnoresClientSuppliedRole()
    {
        using var factory = CreateFactory(_databasePath);
        using var client = CreateClient(factory);
        var token = await GetRequestVerificationTokenAsync(client);
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["Username"] = "alice",
            ["Password"] = Password,
            ["Role"] = UserRoles.Admin
        });
        using var loginResponse = await client.PostAsync("/Users/Login", content);
        using var adminResponse = await client.GetAsync("/Admin/Dashboard");

        Assert.That(loginResponse.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(adminResponse.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(adminResponse.Headers.Location?.AbsolutePath, Is.EqualTo("/Users/AccessDenied"));
    }

    private static async Task<HttpResponseMessage> LoginAsync(HttpClient client, string username)
    {
        var token = await GetRequestVerificationTokenAsync(client);
        return await PostLoginAsync(client, token, username, Password);
    }

    private static async Task<string> GetRequestVerificationTokenAsync(
        HttpClient client,
        string path = "/Users/Login")
    {
        using var response = await client.GetAsync(path);
        var html = await response.Content.ReadAsStringAsync();
        var match = Regex.Match(
            html,
            "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(match.Success, Is.True, "The login form should include an antiforgery token.");
        return match.Groups[1].Value;
    }

    private static async Task<HttpResponseMessage> RegisterAsync(
        HttpClient client,
        string username,
        string email)
    {
        var token = await GetRequestVerificationTokenAsync(client, "/Users/Register");
        return await PostRegistrationAsync(client, token, username, email, Password);
    }

    private static async Task<HttpResponseMessage> PostRegistrationAsync(
        HttpClient client,
        string token,
        string username,
        string email,
        string password)
    {
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["Username"] = username,
            ["Email"] = email,
            ["Password"] = password,
            ["ConfirmPassword"] = password
        });
        return await client.PostAsync("/Users/Register", content);
    }

    private static async Task<HttpResponseMessage> PostLoginAsync(
        HttpClient client,
        string token,
        string username,
        string password)
    {
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["Username"] = username,
            ["Password"] = password
        });
        return await client.PostAsync("/Users/Login", content);
    }

    private static WebApplicationFactory<Program> CreateFactory(string databasePath)
    {
        var connectionString = CreateConnectionString(databasePath);
        return new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseContentRoot(Path.GetFullPath(
                    Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "src")));
                builder.ConfigureTestServices(services =>
                {
                    services.RemoveAll<UserRepository>();
                    services.AddSingleton(new UserRepository(connectionString));
                });
            });
    }

    private static HttpClient CreateClient(WebApplicationFactory<Program> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true,
            AllowAutoRedirect = false
        });

    private static string CreateConnectionString(string databasePath) =>
        new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Pooling = false
        }.ToString();

    private static void DeleteDatabaseFiles(string databasePath)
    {
        File.Delete(databasePath);
        File.Delete(databasePath + "-wal");
        File.Delete(databasePath + "-shm");
    }
}
