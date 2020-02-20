using System.Collections.Generic;

namespace Audit_Scanner.Vulnerability.Models
{
    public class DeviceModel
    {
        public string IP { get; set; }
        
        public string Hostname { get; set; }
        
        public string PhysicalAddress { get; set; }
        
        public string Vendor { get; set; }
        public List<VulnerabilityModel> Vulnerabilities { get; set; }
    }
}