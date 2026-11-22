using System.Net;
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
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Pooling = false
        }.ToString();
        var factory = new WebApplicationFactory<Program>()
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

        try
        {
            using var client = factory.CreateClient();
            const string username = "<script>alert(1)</script>";
            const string email = "<script>alert(2)</script>";
            var response = await client.GetAsync(
                $"/Users/LoggedIn?Username={Uri.EscapeDataString(username)}&Email={Uri.EscapeDataString(email)}");
            var html = await response.Content.ReadAsStringAsync();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("&lt;script&gt;alert(1)&lt;/script&gt;"));
            Assert.That(html, Does.Contain("&lt;script&gt;alert(2)&lt;/script&gt;"));
            Assert.That(html, Does.Not.Contain(username));
            Assert.That(html, Does.Not.Contain(email));
        }
        finally
        {
            factory.Dispose();
            DeleteDatabaseFiles(databasePath);
        }
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
