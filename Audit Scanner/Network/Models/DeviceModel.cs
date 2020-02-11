using System.Collections.Generic;

namespace Audit_Scanner.Network.Models
{
    public class DeviceModel
    {
        public string DeviceName { get; set; }
        public List<ServiceModel> Services { get; set; }
    }
}