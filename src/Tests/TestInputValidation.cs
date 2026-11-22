using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using NUnit.Framework;
using SafeVault.Data;

[TestFixture]
public class TestInputValidation
{
    private string _databasePath = null!;
    private UserRepository _repository = null!;

    [SetUp]
    public async Task SetUp()
    {
        _databasePath = CreateDatabasePath();
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Pooling = false
        }.ToString();
        _repository = new UserRepository(connectionString);
        await _repository.InitializeAsync();

        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO Users (Username, Email) VALUES (@Username, @Email)";
        command.Parameters.Add("@Username", SqliteType.Text).Value = "alice";
        command.Parameters.Add("@Email", SqliteType.Text).Value = "alice@example.com";
        await command.ExecuteNonQueryAsync();
    }

    [TearDown]
    public void TearDown()
    {
        DeleteDatabaseFiles(_databasePath);
    }

    [Test]
    public async Task UsernameCount_ReturnsExistingUser()
    {
        var count = await _repository.FindUserCountWithSameUsername("alice");

        Assert.That(count, Is.EqualTo(1));
    }

    [TestCase("alice' OR 1=1 --")]
    [TestCase("alice' UNION SELECT 1 --")]
    public async Task UsernameCount_TreatsSqlInjectionAsLiteral(string input)
    {
        var count = await _repository.FindUserCountWithSameUsername(input);

        Assert.That(count, Is.Zero);
    }

    [TestCase("<script>alert(1)</script>")]
    [TestCase("<img src=x onerror=alert(1)>")]
    public void UsernameValidationRejectsMarkup(string input)
    {
        Assert.That(ValidationHelper.IsValidUsername(input), Is.False);
    }

    [Test]
    public async Task LoggedInView_EncodesInjectedScriptsInUserInput()
    {
        var databasePath = CreateDatabasePath();
        var factory = CreateFactory(databasePath);

        try
        {
            using var client = factory.CreateClient();
            const string username = "<script>alert(1)</script>";
            const string email = "<script>alert(2)</script>";
            var token = await GetRequestVerificationTokenAsync(client);
            var response = await PostLoginAsync(client, token, username, email);
            var html = await response.Content.ReadAsStringAsync();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("&lt;script&gt;alert(1)&lt;/script&gt;"));
            Assert.That(html, Does.Contain("&lt;script&gt;alert(2)&lt;/script&gt;"));
            Assert.That(html, Does.Not.Contain(username));
            Assert.That(html, Does.Not.Contain(email));
            Assert.That(response.Headers.GetValues("Content-Security-Policy").Single(),
                Does.Contain("object-src 'none'"));
            Assert.That(response.Headers.GetValues("X-Content-Type-Options").Single(), Is.EqualTo("nosniff"));
        }
        finally
        {
            factory.Dispose();
            DeleteDatabaseFiles(databasePath);
        }
    }

    [Test]
    public async Task LoginPost_RequiresAntiforgeryToken()
    {
        var databasePath = CreateDatabasePath();
        var factory = CreateFactory(databasePath);

        try
        {
            using var client = factory.CreateClient();
            using var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Username"] = "alice",
                ["Email"] = "alice@example.com"
            });

            var response = await client.PostAsync("/Users/Login", content);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }
        finally
        {
            factory.Dispose();
            DeleteDatabaseFiles(databasePath);
        }
    }

    [Test]
    public async Task LoginPost_DoesNotPutUserDataInRedirectUrl()
    {
        var databasePath = CreateDatabasePath();
        var factory = CreateFactory(databasePath);

        try
        {
            using var client = factory.CreateClient();
            var token = await GetRequestVerificationTokenAsync(client);
            var response = await PostLoginAsync(client, token, "alice", "alice@example.com");

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(response.RequestMessage!.RequestUri!.Query, Is.Empty);
            Assert.That(response.Headers.GetValues("Cache-Control").Single(), Is.EqualTo("no-store"));
        }
        finally
        {
            factory.Dispose();
            DeleteDatabaseFiles(databasePath);
        }
    }

    private static WebApplicationFactory<Program> CreateFactory(string databasePath)
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Pooling = false
        }.ToString();

        return new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseContentRoot(Path.GetFullPath(
                    Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..")));
                builder.ConfigureAppConfiguration((_, configuration) =>
                    configuration.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["ConnectionStrings:DefaultConnection"] = connectionString
                    }));
            });
    }

    private static async Task<string> GetRequestVerificationTokenAsync(HttpClient client)
    {
        var response = await client.GetAsync("/Users/Login");
        var html = await response.Content.ReadAsStringAsync();
        var match = Regex.Match(
            html,
            "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(match.Success, Is.True, "The login form should include an antiforgery token.");
        return match.Groups[1].Value;
    }

    private static Task<HttpResponseMessage> PostLoginAsync(
        HttpClient client,
        string token,
        string username,
        string email)
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["Username"] = username,
            ["Email"] = email
        });
        return client.PostAsync("/Users/Login", content);
    }

    private static string CreateDatabasePath() =>
        Path.Combine(Path.GetTempPath(), $"SafeVault.Tests.{Guid.NewGuid():N}.db");

    private static void DeleteDatabaseFiles(string databasePath)
    {
        File.Delete(databasePath);
        File.Delete(databasePath + "-wal");
        File.Delete(databasePath + "-shm");
    }
}
