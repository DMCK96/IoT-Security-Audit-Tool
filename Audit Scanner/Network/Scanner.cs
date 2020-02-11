using System;
using System.Collections.Generic;
using Audit_Scanner.Network.Models;
using SaltwaterTaffy;

namespace Audit_Scanner.Network
{
    public class Scanner
    {
        public List<DeviceModel> Devices { get; set; }

        public List<DeviceModel> HostDiscover(int range)
        {
            Devices = new List<DeviceModel>();
            
            
            
            return Devices;
        }
        
        public List<DeviceModel> VulnerabilityScan(List<DeviceModel> devices)
        {

            return devices;
        }
    }
}