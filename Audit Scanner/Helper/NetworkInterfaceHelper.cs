using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace Audit_Scanner.Helper
{
    public class NetworkInterfaceHelper
    {
        public static List<string> GetLocalIPAddresses()
        {
            var list = new List<string>();

            var adapters = NetworkInterface.GetAllNetworkInterfaces();

            foreach (var adapter in adapters)
            {
                var unicastAddresses = adapter.GetIPProperties().UnicastAddresses;

                foreach (var address in unicastAddresses)
                {
                    if (address.PrefixLength == 24)
                    {
                        var ipString = address.Address.ToString();
                        var updated = ipString.Substring(0, ipString.LastIndexOf(".", StringComparison.Ordinal) + 1);
                        updated = updated + "0";
                        list.Add(updated);
                    }
                }
            }
            
            return list;
        }
    }
}