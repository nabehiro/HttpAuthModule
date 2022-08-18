using System;
using System.Linq;
using System.Net;
using System.Web;

namespace HttpAuthModule
{
    /// <summary>
    /// Implements the Restricted IP authentication strategy.
    /// </summary>
    internal class RestrictIPStrategy : IAuthStrategy
    {
        private IPAddressRange[] _ranges;

        /// <summary>
        /// Initializes a new instance of the
        /// <see cref="RestrictIPStrategy"/> class.
        /// </summary>
        public RestrictIPStrategy(string ipAddresses)
        {
            _ranges = ipAddresses.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => new IPAddressRange(s))
                .ToArray();
        }

        /// <inheritdoc/>
        public bool Execute(HttpApplication app)
        {
            foreach (var ip in HttpAuthModule.GetClientIPAddresses(app))
            {
                if (_ranges.Any(a => a.IsInRange(ip)))
                    return true;
            }

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
