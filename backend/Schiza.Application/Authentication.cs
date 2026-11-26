namespace Schiza.Application;

public interface IAuthenticationService
{
    bool Authenticate(string username, string password);
}
