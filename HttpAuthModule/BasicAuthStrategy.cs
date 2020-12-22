using System;
using System.Linq;
using System.Text;
using System.Web;

namespace HttpAuthModule
{
    internal class BasicAuthStrategy : CredentialAuthStrategy
    {
        private string[] _validAuthVals;

        public BasicAuthStrategy()
            : base()
        {
            _validAuthVals = Credentials
                .Select(c => "Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(c.Name + ":" + c.Password)))
                .ToArray();
        }

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
