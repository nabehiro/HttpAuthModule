namespace HttpAuthModule
{
    using System;
    using System.Configuration;
    using System.Linq;
    using System.Web;

    /// <summary>
    /// Implements the Credentials authentication strategy.
    /// </summary>
    internal abstract class CredentialAuthStrategy
        : IAuthStrategy
    {
        /// <summary>
        /// Initializes a new instance of the
        /// <see cref="CredentialAuthStrategy"/> class.
        /// </summary>
        public CredentialAuthStrategy()
        {
            this.Realm = Config.Get("Realm", "SecureZone");

            this.Credentials = Config.Get("Credentials")
                .Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(
                    str =>
                    {
                        var array = str.Trim().Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);

                        if (array.Length != 2)
                        {
                            throw new InvalidOperationException("Credentials is invalid.");
                        }

                        return new Credential { Name = array[0], Password = array[1] };
                    })
                .ToArray();

            if (this.Credentials.Length == 0)
            {
                throw new InvalidOperationException("Credentials is invalid.");
            }
        }

        /// <summary>
        /// Gets or sets the realm.
        /// </summary>
        protected string Realm { get; set; }

        /// <summary>
        /// Gets or sets the credentials.
        /// </summary>
        protected Credential[] Credentials { get; set; }

        /// <inheritdoc/>
        public abstract bool Execute(HttpApplication app);

        /// <summary>
        /// Sends a 401 HTTP status code response to the request.
        /// </summary>
        /// <param name="app">
        /// The HTTP application.
        /// </param>
        /// <param name="wwwAuthenticate">
        /// The WWW-Authenticate header.
        /// </param>
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