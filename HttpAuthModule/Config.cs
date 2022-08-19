namespace HttpAuthModule
{
    using System.Collections.Specialized;
    using System.Configuration;

    /// <summary>
    /// Represents the <see cref="HttpAuthModule"/>
    /// configuration section.
    /// </summary>
    internal static class Config
    {
        private static readonly NameValueCollection Section =
            (NameValueCollection)ConfigurationManager.GetSection("httpAuthModule");

        /// <summary>
        /// Returns the value of the configuration key.
        /// </summary>
        /// <param name="key">
        /// The configuration key.
        /// </param>
        /// <param name="nullVal">
        /// The default value.
        /// </param>
        /// <returns>
        /// The value of the configuration key or
        /// the default value, if it does not exist.
        /// </returns>
        public static string Get(string key, string nullVal = "")
        {
            var val = ConfigurationManager.AppSettings["HttpAuthModule." + key] ?? Section[key];
            return string.IsNullOrEmpty(val) ? nullVal : val;
        }
    }
}