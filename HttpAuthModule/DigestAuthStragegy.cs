using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace HttpAuthModule
{
    internal class DigestAuthStragegy : CredentialAuthStrategy
    {
        private TimeSpan _nonceValidDuration;
        private string _nonceSalt;

        private Dictionary<string, string> _validTokens;

        public DigestAuthStragegy()
            : base()
        {
            var nonceValidDuration = Config.Get("DigestNonceValidDuration", "120");
            var intNonceValidDuration = 0;
            if (!int.TryParse(nonceValidDuration, out intNonceValidDuration) || intNonceValidDuration <= 0)
                throw new InvalidOperationException("DigestNonceValidDuration is invalid.");
            _nonceValidDuration = new TimeSpan(0, intNonceValidDuration, 0);

            _nonceSalt = Config.Get("DigestNonceSalt");
            if (string.IsNullOrEmpty(_nonceSalt))
                throw new InvalidOperationException("DigestNonceSalt is required.");

            _validTokens = Credentials
                .ToDictionary(c => c.Name, c => GetMD5(string.Format("{0}:{1}:{2}", c.Name, Realm, c.Password)));
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
            var a2 = GetMD5(app.Context.Request.HttpMethod + ":" + uri);

            if (response != GetMD5(string.Format("{0}:{1}:{2}:{3}:{4}:{5}", a1, nonce, nc, cnonce, qop, a2)))
                return RespondError(app);

            return true;
        }

        private bool RespondError(HttpApplication app)
        {
            Respond401(app, string.Format(@"Digest realm=""{0}"", nonce=""{1}"", algorithm=MD5, qop=""auth""",
                Realm, CreateNonce(DateTime.UtcNow)));
            return false;
        }

        private string CreateNonce(DateTime dt)
        {
            string hash = string.Format("{0}{1}", _nonceSalt, dt.Ticks);
            for (int i = 0; i < 3; i++) hash = GetSHA1(hash);
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

        private static string GetMD5(string s)
        {
            var md5 = MD5.Create();
            return string.Concat(md5.ComputeHash(Encoding.UTF8.GetBytes(s)).Select(d => d.ToString("x2"))).ToLower();
        }

        private static string GetSHA1(string s)
        {
            var sha1 = SHA1.Create();
            return string.Concat(sha1.ComputeHash(Encoding.UTF8.GetBytes(s)).Select(d => d.ToString("x2"))).ToLower();
        }
    }
}
