public interface IAuthService
{
    Task<object> AuthenticateUserAsync(string username, string password);
}
