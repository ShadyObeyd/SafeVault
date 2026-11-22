using System.ComponentModel.DataAnnotations;

public sealed record LoginViewModel
{
    [Required]
    [StringLength(50)]
    public required string Username { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [StringLength(72)]
    public required string Password { get; set; }
}

public sealed record RegisterViewModel
{
    [Required]
    [StringLength(50)]
    public required string Username { get; set; }

    [Required]
    [EmailAddress]
    [StringLength(100)]
    public required string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [StringLength(72, MinimumLength = 12)]
    public required string Password { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [Compare(nameof(Password))]
    public required string ConfirmPassword { get; set; }
}

public sealed record UserViewModel
{
    [Required]
    [StringLength(50)]
    public required string Username { get; set; }

    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    [Required]
    public required string Role { get; set; }
}