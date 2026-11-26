using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Configuration;

using Schiza.Application;

namespace Schiza.Infrastructure;

public sealed class ConfigurationAuthenticationService(IConfiguration configuration) : IAuthenticationService
{
    public bool Authenticate(string username, string password)
    {
        string configuredUsername = configuration["Admin:Username"] ?? "admin";
        string encodedHash = configuration["Admin:PasswordHash"] ?? "";
        if (!string.Equals(username, configuredUsername, StringComparison.Ordinal)) return false;
        try
        {
            string[] parts = encodedHash.Split('.');
            if (parts.Length != 4 || parts[0] != "pbkdf2" || parts[1] != "sha256") return false;
            byte[] salt = Convert.FromBase64String(parts[2]);
            byte[] expected = Convert.FromBase64String(parts[3]);
            byte[] actual = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, 120_000, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException) { return false; }
    }
}
