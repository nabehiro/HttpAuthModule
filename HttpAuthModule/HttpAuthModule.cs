using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;

namespace HttpAuthModule
{
    public class HttpAuthModule : IHttpModule
    {
        private static object _lock = new object();
        private static bool _initialized = false;
        private static bool _enabled = true;
        private static List<IAuthStrategy> _authStrategies = new List<IAuthStrategy>();
        private static Regex _ignorePathRegex = null;
        private static IPAddressRange[] _ignoreIPAddresses = null;
        private static string[] _clientIPHeaders = null;
        private static string[] _clientIPServerVariables = null;

        public void Dispose() { }

        public void Init(HttpApplication context)
        {
            InitializeStatic();
            if (_enabled)
                context.AuthenticateRequest += new EventHandler(context_AuthenticateRequest);
        }

        private void InitializeStatic()
        {
            if (!_initialized)
            {
                lock (_lock)
                {
                    if (!_initialized)
                    {
                        try
                        {
                            _enabled = bool.Parse(ConfigurationManager.AppSettings["HttpAuthModuleEnabled"] ?? "true");
                        }
                        catch(Exception ex)
                        {
                            throw new InvalidOperationException("AppSettings[HttpAuthModuleEnabled] is invalid.", ex);
                        }

                        var restrictIPAddresses = Config.Get("RestrictIPAddresses");
                        if (!string.IsNullOrEmpty(restrictIPAddresses))
                            _authStrategies.Add(new RestrictIPStrategy(restrictIPAddresses));

                        switch (Config.Get("AuthMode").ToLower())
                        {
                            case "basic": _authStrategies.Add(new BasicAuthStrategy()); break;
                            case "digest": _authStrategies.Add(new DigestAuthStrategy()); break;
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

                        var ignoreIPAddresses = Config.Get("ignoreIPAddresses");
                        if (!string.IsNullOrEmpty(ignoreIPAddresses))
                            _ignoreIPAddresses = ignoreIPAddresses.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                                .Select(s => new IPAddressRange(s))
                                .ToArray();

                        var clientIPHeaders = Config.Get("clientIPHeaders");
                        if (!string.IsNullOrEmpty(clientIPHeaders))
                            _clientIPHeaders = clientIPHeaders.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

                        var clientIPServerVariables = Config.Get("clientIPServerVariables");
                        if (!string.IsNullOrEmpty(clientIPServerVariables))
                            _clientIPServerVariables = clientIPServerVariables.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

                        _initialized = true;
                    }
                }
            }
        }

        public static IEnumerable<string> GetClientIPAddresses(HttpApplication app)
        {
            var ip = app.Context.Request.UserHostAddress;
            if (!string.IsNullOrEmpty(ip))
                yield return ip;

            if (_clientIPHeaders != null)
            {
                foreach (var key in _clientIPHeaders)
                {
                    ip = app.Context.Request.Headers[key];
                    if (!string.IsNullOrEmpty(ip))
                        yield return ip;
                }
            }

            if (_clientIPServerVariables != null)
            {
                foreach (var key in _clientIPServerVariables)
                {
                    ip = app.Context.Request.ServerVariables[key];
                    if (!string.IsNullOrEmpty(ip))
                        yield return ip;
                }
            }
        }

        private void context_AuthenticateRequest(object sender, EventArgs e)
        {
            var app = (HttpApplication)sender;

            if (_ignoreIPAddresses != null)
            {
                foreach (var ip in GetClientIPAddresses(app))
                {
                    if (_ignoreIPAddresses.Any(a => a.IsInRange(ip)))
                        return;
                }
            }

            if (_ignorePathRegex != null && _ignorePathRegex.IsMatch(app.Context.Request.RawUrl))
                return;

            foreach (var s in _authStrategies)
            {
#if DEBUG
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var result = s.Execute((HttpApplication)sender);
                sw.Stop();
                System.Diagnostics.Trace.WriteLine(string.Format("{0} ({1}) - {2} | {3}", s.GetType(), result, sw.Elapsed, app.Request.RawUrl));
                if (!result) break;
#else
                if (!s.Execute(app)) break;
#endif
            }
        }
    }
}
