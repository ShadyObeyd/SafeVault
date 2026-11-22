using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SafeVault.Models;

[Table("Users")]
public sealed class User
{
    public int Id { get; set; }

    [Required]
    [MaxLength(100)]
    [Column(TypeName = "VARCHAR(100)")]
    public required string Username { get; set; }

    [Required]
    [MaxLength(100)]
    [Column(TypeName = "VARCHAR(100)")]
    public required string Email { get; set; }
}
