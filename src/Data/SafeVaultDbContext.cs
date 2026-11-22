using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Data;

public sealed class SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options)
    : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
}
