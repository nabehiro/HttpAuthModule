using System;
using System.Collections.Generic;
using System.Configuration;
using System.Text.RegularExpressions;
using System.Web;

namespace HttpAuthModule
{
    public class HttpAuthModule : IHttpModule
    {
        private static object _lock = new object();
        private static bool _initialized = false;
        private static List<IAuthStrategy> _authStrategies = new List<IAuthStrategy>();
        private static Regex _ignorePathRegex = null;

        public void Dispose() { }

        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest += new EventHandler(context_AuthenticateRequest);
        }

        private void context_AuthenticateRequest(object sender, EventArgs e)
        {
            if (!_initialized)
            {
                lock (_lock)
                {
                    if (!_initialized)
                    {
                        var restrictIPAddresses = Config.Get("RestrictIPAddresses");
                        if (!string.IsNullOrEmpty(restrictIPAddresses))
                            _authStrategies.Add(new RestictIPStragegy(restrictIPAddresses));

                        switch (Config.Get("AuthMode").ToLower())
                        {
                            case "basic": _authStrategies.Add(new BasicAuthStragegy()); break;
                            case "digest": _authStrategies.Add(new DigestAuthStragegy()); break;
                            case "none": break;
                            default: throw new InvalidOperationException("AuthMode must be Basic, Digest or None.");
                        }

                        var ignorePathRegex = Config.Get("IgnorePathRegex");
                        if (!string.IsNullOrEmpty(ignorePathRegex))
                        {
                            try
                            {
                                _ignorePathRegex = new Regex(ignorePathRegex, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                            }
                            catch (Exception ex)
                            {
                                throw new InvalidOperationException("IgnorePathRegex is invalid.", ex);
                            }
                        }

                        _initialized = true;
                    }
                }
            }

            var app = (HttpApplication)sender;

            if (_ignorePathRegex != null && _ignorePathRegex.IsMatch(app.Context.Request.RawUrl))
                return;

            foreach (var s in _authStrategies)
            {
#if DEBUG
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var result = s.Execute((HttpApplication)sender);
                sw.Stop();
                System.Diagnostics.Trace.WriteLine(string.Format("{0} ({1}) - {2}", s.GetType(), result, sw.Elapsed));
                if (!result) break;
#else
                if (!s.Execute(app)) break;
#endif
            }
        }
    }
}
