using System;
using System.Collections.Generic;
using System.Linq;
using Audit_Scanner.Controllers.Vulnerability;
using Audit_Scanner.Helper;
using Audit_Scanner.Network.Models;
using RestSharp;
using SaltwaterTaffy;
using SaltwaterTaffy.Container;

namespace Audit_Scanner.Network
{
    public class AuditScanner
    {
        public List<DeviceModel> Devices { get; } = new List<DeviceModel>();

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

                foreach (var address in localIpAddresses)
                {
                    target = new Target($"{address}/{range}");
                    foundHosts.AddRange(new Scanner(target).HostDiscovery());
                }
            }
            
            return foundHosts;
        }
        
        public List<DeviceModel> VulnerabilityScan(List<DeviceModel> devices)
        {
            var client = new VulnerabilityClient();

            /*foreach (var device in result)
            {
                var singleDevice = new DeviceModel();
                singleDevice.Address = device.Address;
                singleDevice.Name = device.OsMatches.FirstOrDefault().Name;
                singleDevice.OpenPorts = device.Ports.ToList();

                foreach (var port in device.Ports)
                {
                    var singleService = new ServiceModel();
                    singleService.Name = port.Service.Name;
                    singleService.Version = port.Service.Version;
                    singleService.Port = port.PortNumber.ToString();
                }

                Devices.Add(singleDevice);
            }*/
            
            return client.ScanVulnerabilities(devices);
        }
    }
}