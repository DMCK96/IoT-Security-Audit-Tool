using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Audit_Scanner.Controllers.Vulnerability;
using Audit_Scanner.Helper;
using Audit_Scanner.Vulnerability.Models;
using RestSharp;
using SaltwaterTaffy;
using SaltwaterTaffy.Container;

namespace Audit_Scanner.Network
{
    public class AuditScanner
    {
        public List<string> LocalIPList = NetworkInterfaceHelper.GetLocalIpList();
        
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
                var localIpRanges = NetworkInterfaceHelper.ConvertLocalIpToRange(LocalIPList);
                
                foreach (var address in localIpRanges.Where(x => !x.Contains("100.74.172.0"))) //exclude my apartment building
                {
                    target = new Target($"{address}/{range}");
                    var discovery = new Scanner(target).HostDiscovery();
                    foundHosts.AddRange(discovery);
                }
            }
            
            return foundHosts;
        }

        public List<Host> ServiceScan(List<Host> devices)
        {
            var updatedDevices = new List<Host>();
            
            //Exclude localhost based on local IP list. 
            foreach (var device in devices.Where(x => !LocalIPList.Contains(x.Address.ToString())))
            {
                var services = new Scanner(new Target(device.Address)).ServiceDiscovery();

                if (services.FirstOrDefault().Ports.Count() > 0) 
                {
                    // No reason to audit a device that has no open ports
                    updatedDevices.AddRange(services);
                }
            }
            
            return updatedDevices;
        }

        public List<DeviceModel> CveScan(List<Host> devices)
        {
            var deviceList = new List<DeviceModel>();

            foreach (var device in devices)
            {
                var Cve = new Scanner(new Target(device.Address)).VulnerabilityDiscovery();
            }
            
            return deviceList;
        }
        
        public List<DeviceModel> VulnerabilityScan(List<Host> devices)
        {
            var client = new VulnerabilityClient();

            return client.ScanVulnerabilities(devices);
        }
    }
}