﻿using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace HttpAuthModule
{
    internal class IPAddressRange
    {
        private AddressFamily _addressFamily;
        private byte[] _networkAddressBytes;
        private byte[] _subnetMaskBytes;

        /// <param name="ipRangeStr">
        /// e.g)
        /// "10.23.0.0/24",
        /// "127.0.0.1" (equals to "127.0.0.1/32"),
        /// "2001:0db8:bd05:01d2:288a:1fc0:0001:0000/16",
        /// "::1" (equals to "::1/128")
        /// </param>
        public IPAddressRange(string ipRangeString)
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

            _networkAddressBytes = ipAddr.GetAddressBytes();
            _subnetMaskBytes = Enumerable.Repeat<byte>(0xFF, _networkAddressBytes.Length).ToArray();

            for (int i = 0; i < (maxMaskRange - maskRange); i++)
                _subnetMaskBytes[_subnetMaskBytes.Length - 1 - i / 8] -= (byte)(1 << (i % 8));
        }

        public bool IsInRange(IPAddress ipAddr)
        {
            if (ipAddr.AddressFamily != _addressFamily)
                return false;

            var addrBytes = ipAddr.GetAddressBytes();
            for (int i = 0; i < addrBytes.Length; i++)
                if ((addrBytes[i] & _subnetMaskBytes[i]) != _networkAddressBytes[i])
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
}
