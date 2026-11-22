public static class ValidationHelper
{
    private static readonly string allowedSpecialCharacters = "!@#$%^&*?";

    public static bool IsValidInput(string input)
    {
        if (string.IsNullOrWhiteSpace(input?.Trim()))
        {
            return false;
        }

        var validCharacters = allowedSpecialCharacters.ToHashSet();

        return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
    }

    public static bool IsValidXSSInput(string input)
    {
        if (string.IsNullOrWhiteSpace(input?.Trim()))
        {
            return false;
        }

        if (input.Contains("<script") || input.Contains("<iframe"))
        {
            return false;
        }

        return true;
    }
}