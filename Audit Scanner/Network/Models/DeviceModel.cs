using System.Collections.Generic;

namespace Audit_Scanner.Network.Models
{
    public class DeviceModel
    {
        public string Name { get; set; }
        public string Address { get; set; }
        public List<int> OpenPorts { get; set; }
        public List<ServiceModel> Services { get; set; }
    }
}