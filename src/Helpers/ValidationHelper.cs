public static class ValidationHelper
{
    private const string AllowedUsernameSpecialCharacters = "!@#$%^&*?";

    public static bool IsValidUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username) || username.Length > 50)
        {
            return false;
        }

        return username.All(character =>
            char.IsLetterOrDigit(character) || AllowedUsernameSpecialCharacters.Contains(character));
    }
}