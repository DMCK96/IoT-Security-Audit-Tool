using Audit_Scanner.Vulnerability.Models;

namespace Audit_Scanner.Network.Models
{
    public class ServiceModel
    {
        public string Name { get; set; }
        public string Port { get; set; }
        public string Version { get; set; }
        public bool Vulnerable { get; set; }
        public VulnerabilityModel Vulnerability { get; set; }
    }
}