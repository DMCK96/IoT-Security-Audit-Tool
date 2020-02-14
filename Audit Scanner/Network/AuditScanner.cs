using System;
using System.Collections.Generic;
using System.Linq;
using Audit_Scanner.Network.Models;
using RestSharp;
using SaltwaterTaffy;
using SaltwaterTaffy.Container;

namespace Audit_Scanner.Network
{
    public class AuditScanner
    {
        public List<DeviceModel> Devices { get; } = new List<DeviceModel>();

        public List<DeviceModel> HostDiscover(string ip, bool known, string range = "24")
        {
            Target target;
            target = known ? new Target(ip) : new Target($"{ip}/{range}");
            var result = new Scanner(target).HostDiscovery();

            foreach (var device in result)
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
            }
            
            return Devices;
        }
        
        public List<DeviceModel> VulnerabilityScan(List<DeviceModel> devices)
        {
            var rest = new RestClient();
                
            foreach (var device in devices)
            {
                
            }
            return devices;
        }
    }
}