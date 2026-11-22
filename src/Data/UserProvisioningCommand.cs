using System.Text;
using SafeVault.Security;

namespace SafeVault.Data;

public static class UserProvisioningCommand
{
    public static async Task RunAsync(UserRepository userRepository)
    {
        Console.Write("Username: ");
        var username = Console.ReadLine() ?? string.Empty;
        Console.Write("Email: ");
        var email = Console.ReadLine() ?? string.Empty;
        Console.Write($"Role ({UserRoles.User}/{UserRoles.Admin}): ");
        var role = Console.ReadLine() ?? string.Empty;

        var password = ReadPassword("Password: ");
        var confirmation = ReadPassword("Confirm password: ");
        if (!string.Equals(password, confirmation, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Passwords do not match.");
        }

        if (!await userRepository.CreateUserAsync(username, email, password, role))
        {
            throw new InvalidOperationException("A user with that username already exists.");
        }

        Console.WriteLine("User provisioned.");
    }

    private static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        var password = new StringBuilder();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return password.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0)
                {
                    password.Length--;
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                password.Append(key.KeyChar);
            }
        }
    }
}
