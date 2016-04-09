using System.Collections.Specialized;
using System.Configuration;

namespace HttpAuthModule
{
    internal static class Config
    {
        private static readonly NameValueCollection _section =
            (NameValueCollection)ConfigurationManager.GetSection("httpAuthModule");

        public static string Get(string key, string nullVal = "")
        {
            var val = ConfigurationManager.AppSettings["HttpAuthModule." + key] ?? _section[key];
            return string.IsNullOrEmpty(val) ? nullVal : val;
        }
    }
}
