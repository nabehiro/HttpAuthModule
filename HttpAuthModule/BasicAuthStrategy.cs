using System;
using System.Linq;
using System.Text;
using System.Web;

namespace HttpAuthModule
{
    /// <summary>
    /// Implements the Basic authentication strategy.
    /// </summary> 
    internal class BasicAuthStrategy : CredentialAuthStrategy
    {
        private string[] _validAuthVals;

        /// <summary>
        /// Initializes a new instance of the
        /// <see cref="BasicAuthStrategy"/> class.
        /// </summary>
        public BasicAuthStrategy()
            : base()
        {
            _validAuthVals = Credentials
                .Select(c => "Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(c.Name + ":" + c.Password)))
                .ToArray();
        }

        /// <inheritdoc/>
        public override bool Execute(HttpApplication app)
        {
            var authVal = app.Context.Request.Headers["Authorization"];
            if (!_validAuthVals.Contains(authVal))
            {
                Respond401(app, "Basic Realm=" + Realm);
                return false;
            }
            return true;
        }
    }

}
