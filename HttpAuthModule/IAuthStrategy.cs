using System.Web;

namespace HttpAuthModule
{
    internal interface IAuthStrategy
    {
        bool Execute(HttpApplication app);
    }
}
