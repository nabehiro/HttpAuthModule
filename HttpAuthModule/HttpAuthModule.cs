using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Security;

namespace HttpAuthModule
{
    public class HttpAuthModule : IHttpModule
    {
        private static object _lock = new object();
        private static bool _initialized = false;
        private static List<IAuthStrategy> _authStrategies = new List<IAuthStrategy>();

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
                        switch ((ConfigurationManager.AppSettings["HttpAuth"] ?? "").ToLower())
                        {
                            case "basic": _authStrategies.Add(new BasicAuthStragegy()); break;
                            case "digest": _authStrategies.Add(new DigestAuthStragegy()); break;
                            case "none": break;
                            default: throw new InvalidOperationException("AppSettings[HttpAuth] must be Basic, Digest or None.");
                        }

                        var restrictIPAddresses = ConfigurationManager.AppSettings["HttpAuth.RestrictIPAddresses"];
                        if (!string.IsNullOrEmpty(restrictIPAddresses))
                            _authStrategies.Add(new RestictIPStragegy(restrictIPAddresses));

                        _initialized = true;
                    }
                }
            }

            foreach (var s in _authStrategies)
            {
#if DEBUG
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var result = s.Execute((HttpApplication)sender);
                sw.Stop();
                System.Diagnostics.Trace.WriteLine(string.Format("{0} ({1}) - {2}", s.GetType(), result, sw.Elapsed));
                if (!result) break;
#else
                if (!s.Execute((HttpApplication)sender)) break;
#endif
            }
        }

        public class Credential
        {
            public string Name { get; set; }
            public string Password { get; set; }
        }

        #region IAuthStrategy

        public interface IAuthStrategy
        {
            bool Execute(HttpApplication app);
        }

        #endregion

        #region CredentialAuthStrategy

        public abstract class CredentialAuthStrategy : IAuthStrategy
        {
            protected string Realm { get; set; }
            protected Credential[] Credentials { get; set; }

            public CredentialAuthStrategy()
            {
                Realm = ConfigurationManager.AppSettings["HttpAuth.Realm"];
                Credentials = (ConfigurationManager.AppSettings["HttpAuth.Credentials"] ?? "")
                    .Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(str =>
                    {
                        var array = str.Trim().Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
                        if (array.Length != 2) throw new InvalidOperationException("AppSettings[HttpAuth.Credentials] is invalid.");
                        return new Credential { Name = array[0], Password = array[1] };
                    }).ToArray();
            }

            public abstract bool Execute(HttpApplication app);
        }

        #endregion

        #region BasicAuthStragegy

        public class BasicAuthStragegy : CredentialAuthStrategy
        {
            private string[] _validAuthVals;

            public BasicAuthStragegy()
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
                    app.Context.Response.Clear();
                    app.Context.Response.Status = "401 Unauthorized";
                    app.Context.Response.StatusCode = 401;
                    app.Context.Response.AddHeader("WWW-Authenticate", "Basic Realm=" + Realm);
                    app.Context.Response.End();
                    return false;
                }
                return true;
            }

        }

        #endregion

        #region DigestAuthStragegy

        public class DigestAuthStragegy : CredentialAuthStrategy
        {
            private static readonly TimeSpan _nonceValidDuration = new TimeSpan(2, 0, 0);
            private static readonly string _nonceSalt = Guid.NewGuid().ToString() + Guid.NewGuid().ToString();

            private Dictionary<string, string> _validTokens;

            public DigestAuthStragegy() : base()
            {
                _validTokens = Credentials
                    .ToDictionary(c => c.Name, c => MD5(string.Format("{0}:{1}:{2}", c.Name, Realm, c.Password)));
            }

            public override bool Execute(HttpApplication app)
            {
                var authVal = app.Context.Request.Headers["Authorization"];
                if (string.IsNullOrEmpty(authVal)) 
                    return RespondError(app);

                var vals = Regex.Matches(app.Context.Request.Headers["Authorization"],
                    @"(?<name>\w+)=(""(?<val>[^""]*)""|(?<val>[^"" ,\t\r\n]+))")
                    .Cast<Match>()
                    .ToDictionary(m => m.Groups["name"].Value, m => m.Groups["val"].Value);

                var nonce = vals.ContainsKey("nonce") ? vals["nonce"] : null;
                if (!ValidateNonce(nonce)) 
                    return RespondError(app);

                var username = vals.ContainsKey("username") ? vals["username"] : null;
                if (!_validTokens.ContainsKey(username)) 
                    return RespondError(app);

                var uri = vals.ContainsKey("uri") ? vals["uri"] : null;
                var cnonce = vals.ContainsKey("cnonce") ? vals["cnonce"] : null;
                var qop = vals.ContainsKey("qop") ? vals["qop"] : null;
                var nc = vals.ContainsKey("nc") ? vals["nc"] : null;
                var response = vals.ContainsKey("response") ? vals["response"] : null;
                var a1 = _validTokens[username];
                var a2 = MD5(app.Context.Request.HttpMethod + ":" + uri);

                if (response != MD5(string.Format("{0}:{1}:{2}:{3}:{4}:{5}", a1, nonce, nc, cnonce, qop, a2)))
                    return RespondError(app);

                return true;
            }

            private bool RespondError(HttpApplication app)
            {
                app.Context.Response.Clear();
                app.Context.Response.Status = "401 Unauthorized";
                app.Context.Response.StatusCode = 401;
                app.Context.Response.AddHeader("WWW-Authenticate",
                    string.Format(@"Digest realm=""{0}"", nonce=""{1}"", algorithm=MD5, qop=""auth""", Realm, CreateNonce(DateTime.UtcNow)));
                app.Context.Response.End();
                return false;
            }

            private string CreateNonce(DateTime dt)
            {
                string hash = string.Format("{0}{1}",_nonceSalt, dt.Ticks);
                for(int i = 0; i < 3; i++) hash = SHA1(hash);
                return string.Format("{0}-{1}", dt.Ticks, hash);
            }
            private bool ValidateNonce(string nonce)
            {
                if (string.IsNullOrEmpty(nonce)) return false;

                DateTime dt;
                try
                {
                    dt = new DateTime(long.Parse(nonce.Split('-')[0]), DateTimeKind.Utc);
                }
                catch
                {
                    return false;
                }
                return dt + _nonceValidDuration >= DateTime.UtcNow && nonce == CreateNonce(dt);
            }

            private static string MD5(string s)
            {
                return FormsAuthentication.HashPasswordForStoringInConfigFile(s, "MD5").ToLower();
            }
            private static string SHA1(string s)
            {
                return FormsAuthentication.HashPasswordForStoringInConfigFile(s, "SHA1").ToLower();
            }
        }

        #endregion

        #region RestictIPStragegy

        public class RestictIPStragegy : IAuthStrategy
        {
            private IPAddressRangeChecker[] _checkers;

            public RestictIPStragegy(string ipAddresses)
            {
                _checkers = ipAddresses.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => new IPAddressRangeChecker(s))
                    .ToArray();
            }

            public bool Execute(HttpApplication app)
            {
                IPAddress ipAddr;
                if (!IPAddress.TryParse(app.Context.Request.UserHostAddress, out ipAddr))
                    return RespondError(app);

                if (_checkers.Any(c => c.IsInRange(ipAddr)))
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

        public class IPAddressRangeChecker
        {
            private AddressFamily _addressFamily;
            private byte[] _netowrkAddressBytes;
            private byte[] _subnetMaskBytes;

            /// <param name="ipRangeStr">
            /// e.g)
            /// "10.23.0.0/24",
            /// "127.0.0.1" (equals to "127.0.0.1/32"),
            /// "2001:0db8:bd05:01d2:288a:1fc0:0001:0000/16",
            /// "::1" (equals to "::1/128")
            /// </param>
            public IPAddressRangeChecker(string ipRangeString)
            {
                if (string.IsNullOrEmpty(ipRangeString))
                    throw new InvalidOperationException("IP Address is null or empty.");

                var vals = ipRangeString.Split('/');
                IPAddress ipAddr;
                if (!IPAddress.TryParse(vals[0], out ipAddr))
                    throw new InvalidOperationException(string.Format("IP Address({0}) is invalid format.", ipRangeString));

                _addressFamily = ipAddr.AddressFamily;
                if (_addressFamily != AddressFamily.InterNetwork && _addressFamily != AddressFamily.InterNetworkV6)
                    throw new InvalidOperationException(string.Format("IP Address({0}) is not ip4 or ip6 address famiry.", ipRangeString));

                var maxMaskRange = _addressFamily == AddressFamily.InterNetwork ? 32 : 128;
                int maskRange;
                if (vals.Length > 1)
                {
                    if (!int.TryParse(vals[1], out maskRange) || maskRange < 0 || maskRange > maxMaskRange)
                        throw new InvalidOperationException(string.Format("IP Address({0}) is invalid range.", ipRangeString));
                }
                else
                    maskRange = maxMaskRange;

                _netowrkAddressBytes = ipAddr.GetAddressBytes();
                _subnetMaskBytes = Enumerable.Repeat<byte>(0xFF, _netowrkAddressBytes.Length).ToArray();

                for (int i = 0; i < (maxMaskRange - maskRange); i++)
                    _subnetMaskBytes[_subnetMaskBytes.Length - 1 - i / 8] -= (byte)(1 << (i % 8));
            }

            public bool IsInRange(IPAddress ipAddr)
            {
                if (ipAddr.AddressFamily != _addressFamily)
                    return false;

                var addrBytes = ipAddr.GetAddressBytes();
                for (int i = 0; i < addrBytes.Length; i++)
                    if ((addrBytes[i] & _subnetMaskBytes[i]) != _netowrkAddressBytes[i])
                        return false;

                return true;
            }
            public bool IsInRange(string ipAddrString)
            {
                IPAddress ipAddr;
                if (!IPAddress.TryParse(ipAddrString, out ipAddr))
                    return false;
                return IsInRange(ipAddr);
            }
        }

        #endregion
    }
}
