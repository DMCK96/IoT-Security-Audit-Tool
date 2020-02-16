using System;
using System.Collections.Generic;
using System.Linq;
using Audit_Scanner.Controllers.Vulnerability;
using Audit_Scanner.Helper;
using RestSharp;
using SaltwaterTaffy;
using SaltwaterTaffy.Container;

namespace Audit_Scanner.Network
{
    public class AuditScanner
    {
        public List<Host> HostDiscover(string ip, bool known, string range = "24")
        {
            Target target;
            var foundHosts = new List<Host>();
            
            if (known)
            {
                target = new Target(ip);
                foundHosts.AddRange(new Scanner(target).HostDiscovery());
            }
            else
            {
                var localIpAddresses = NetworkInterfaceHelper.GetLocalIPAddresses();

                foreach (var address in localIpAddresses.Where(x => !x.Contains("100.74.172.0")))
                {
                    target = new Target($"{address}/{range}");
                    var discovery = new Scanner(target).HostDiscovery();
                    foundHosts.AddRange(discovery.Where(x => x.Ports.Count() > 90)); //LINQ is just to exclude localhost
                }
            }
            
            return foundHosts;
        }
        
        public List<Host> VulnerabilityScan(List<Host> devices)
        {
            var client = new VulnerabilityClient();

            return client.ScanVulnerabilities(devices);
        }
    }
}