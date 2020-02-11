using System.Collections.Generic;
using System.Net;
using SaltwaterTaffy.Container;

namespace Audit_Scanner.Network.Models
{
    public class DeviceModel
    {
        public string Name { get; set; }
        public IPAddress Address { get; set; }
        public List<Port> OpenPorts { get; set; }
        public List<ServiceModel> Services { get; set; }
    }
}