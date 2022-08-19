// Copyright (c) Hiroyuki Watanabe. All rights reserved.

namespace HttpAuthModule
{
    using System;
    using System.Linq;
    using System.Text;
    using System.Web;

    /// <summary>
    /// Implements the Basic authentication strategy.
    /// </summary>
    internal class BasicAuthStrategy
        : CredentialAuthStrategy
    {
        private string[] validAuthVals;

        /// <summary>
        /// Initializes a new instance of the
        /// <see cref="BasicAuthStrategy"/> class.
        /// </summary>
        public BasicAuthStrategy()
            : base()
        {
            this.validAuthVals = this.Credentials
                .Select(c => "Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(c.Name + ":" + c.Password)))
                .ToArray();
        }

        /// <inheritdoc/>
        public override bool Execute(HttpApplication app)
        {
            var authVal = app.Context.Request.Headers["Authorization"];

            if (!this.validAuthVals.Contains(authVal))
            {
                this.Respond401(app, "Basic Realm=" + this.Realm);

                return false;
            }

            return true;
        }
    }
}