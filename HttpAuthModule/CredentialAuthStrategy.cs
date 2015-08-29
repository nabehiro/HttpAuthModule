using System;
using System.Configuration;
using System.Linq;
using System.Web;

namespace HttpAuthModule
{
    internal abstract class CredentialAuthStrategy : IAuthStrategy
    {
        protected string Realm { get; set; }
        protected Credential[] Credentials { get; set; }

        public CredentialAuthStrategy()
        {
            Realm = Config.Get("Realm", "SecureZone");

            Credentials = Config.Get("Credentials")
                .Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(str =>
                {
                    var array = str.Trim().Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
                    if (array.Length != 2) throw new InvalidOperationException("Credentials is invalid.");
                    return new Credential { Name = array[0], Password = array[1] };
                }).ToArray();
            if (Credentials.Length == 0)
                throw new InvalidOperationException("Credentials is invalid.");
        }

        public abstract bool Execute(HttpApplication app);

        protected void Respond401(HttpApplication app, string wwwAuthenticate)
        {
            app.Context.Response.Clear();
            app.Context.Response.Status = "401 Unauthorized";
            app.Context.Response.StatusCode = 401;
            app.Context.Response.AddHeader("WWW-Authenticate", wwwAuthenticate);
            app.Context.Response.SuppressFormsAuthenticationRedirect = true;
            app.Context.Response.End();
        }
    }
}
