using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace Audit_Scanner.Helper
{
    public class NetworkInterfaceHelper
    {
        public static List<string> GetLocalIpList()
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
                        
                        list.Add(ipString);
                    }
                }
            }
            
            return list;
        }

        public static List<string> ConvertLocalIpToRange(List<string> ipList)
        {
            var rangeList = new List<string>();
            
            foreach (var ip in ipList)
            {
                var updated = ip.Substring(0, ip.LastIndexOf(".", StringComparison.Ordinal) + 1);
                updated = updated + "0";
                rangeList.Add(updated);
            }

            return rangeList;
        }
    }
}