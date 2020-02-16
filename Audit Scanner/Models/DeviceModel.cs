using System.Collections.Generic;

namespace Audit_Scanner.Vulnerability.Models
{
    public class DeviceModel
    {
        public string IP { get; set; }
        public List<VulnerabilityModel> Vulnerabilities { get; set; }
    }
}