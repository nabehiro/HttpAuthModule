// Copyright (c) Hiroyuki Watanabe. All rights reserved.

namespace HttpAuthModule
{
    using System;
    using System.Linq;
    using System.Web;

    /// <summary>
    /// Implements the Restricted IP authentication strategy.
    /// </summary>
    internal class RestrictIPStrategy
        : IAuthStrategy
    {
        private IPAddressRange[] ranges;

        /// <summary>
        /// Initializes a new instance of the
        /// <see cref="RestrictIPStrategy"/> class.
        /// </summary>
        /// <param name="ipAddresses">
        /// A semi-colon separated list of IP addresses.
        /// </param>
        public RestrictIPStrategy(string ipAddresses)
        {
            this.ranges = ipAddresses
                .Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => new IPAddressRange(s))
                .ToArray();
        }

        /// <inheritdoc/>
        public bool Execute(HttpApplication app)
        {
            foreach (var ip in HttpAuthModule.GetClientIPAddresses(app))
            {
                if (this.ranges.Any(a => a.IsInRange(ip)))
                {
                    return true;
                }
            }

            return this.RespondError(app);
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