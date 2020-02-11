using System;
using System.Collections.Generic;
using System.Linq;
using Audit_Scanner.Network.Models;
using SaltwaterTaffy;
using SaltwaterTaffy.Container;

namespace Audit_Scanner.Network
{
    public class AuditScanner
    {
        public List<DeviceModel> Devices { get; } = new List<DeviceModel>();

        public List<DeviceModel> HostDiscover(string range)
        {
            var target = new Target($"192.168.0.0/{range}");
            var result = new Scanner(target).HostDiscovery();

            foreach (var device in result)
            {
                var singleDevice = new DeviceModel
                {
                    Address = device.Address,
                    OpenPorts = device.Ports.ToList(),
                };
            }
            
            return Devices;
        }
        
        public List<DeviceModel> VulnerabilityScan(List<DeviceModel> devices)
        {

            return devices;
        }
    }
}