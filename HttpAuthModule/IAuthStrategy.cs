// Copyright (c) Hiroyuki Watanabe. All rights reserved.

namespace HttpAuthModule
{
    using System.Web;

    /// <summary>
    /// Defines the authentication strategy interface.
    /// </summary>
    internal interface IAuthStrategy
    {
        /// <summary>
        /// Authenticates the user.
        /// </summary>
        /// <param name="app">
        /// The HTTP application.
        /// </param>
        /// <returns>
        /// true, if the user was authenticated.
        /// false, otherwise.
        /// </returns>
        bool Execute(HttpApplication app);
    }
}