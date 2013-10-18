using System;
using System.Linq;
using System.Net;
using System.Web;

namespace HttpAuthModule
{
    internal class RestictIPStragegy : IAuthStrategy
    {
        private IPAddressRange[] _ranges;

        public RestictIPStragegy(string ipAddresses)
        {
            _ranges = ipAddresses.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => new IPAddressRange(s))
                .ToArray();
        }

        public bool Execute(HttpApplication app)
        {
            IPAddress ipAddr;
            if (!IPAddress.TryParse(app.Context.Request.UserHostAddress, out ipAddr))
                return RespondError(app);

            if (_ranges.Any(c => c.IsInRange(ipAddr)))
                return true;
            else
                return RespondError(app);
        }

        private bool RespondError(HttpApplication app)
        {
            app.Context.Response.Clear();
            app.Context.Response.Status = "403 Forbidden";
            app.Context.Response.StatusCode = 403;
            app.Context.Response.End();
            return false;
        }
    }
}
