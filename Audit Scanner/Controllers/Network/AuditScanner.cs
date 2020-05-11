using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Timers;
using Audit_Scanner.Controllers.Vulnerability;
using Audit_Scanner.Helper;
using Audit_Scanner.Vulnerability.Models;
using RestSharp;
using SaltwaterTaffy;
using SaltwaterTaffy.Container;

namespace Audit_Scanner.Network
{
    public class AuditScanner
    {
        public List<string> LocalIPList = NetworkInterfaceHelper.GetLocalIpList();
        
        public List<Host> HostDiscover(string ip, bool known, string range = "24")
        {
            Target target;
            var foundHosts = new List<Host>();
            Console.WriteLine("");
            var timer = new Stopwatch();;
            timer.Start();
            
            if (known)
            {
                target = new Target(ip);
                Console.WriteLine($"Host discovery started on {ip}, please wait...");
                foundHosts.AddRange(new Scanner(target).HostDiscovery());
            }
            else
            {
                var localIpRanges = NetworkInterfaceHelper.ConvertLocalIpToRange(LocalIPList);
                
                Console.WriteLine("Host discovery scan started, please wait...");
                
                foreach (var address in localIpRanges.Where(x => !x.Contains("100.74.172.0"))) //exclude my apartment building
                {
                    target = new Target($"{address}/{range}");
                    var discovery = new Scanner(target).HostDiscovery();
                    foundHosts.AddRange(discovery);
                    Console.WriteLine($"Host discovery found {discovery.Count()} online devices in {address}/{range}");
                }
            }
            timer.Stop();
            Console.WriteLine($"Host discovery scan completed, {foundHosts.Count} online devices have been found. Scan took {timer.Elapsed.Seconds} seconds to complete.");
            return foundHosts;
        }

        public List<Host> ServiceScan(List<Host> devices)
        {
            var updatedDevices = new List<Host>();
            
            Console.WriteLine("");
            Console.WriteLine("Service scan started, please wait...");
            
            //Exclude localhost based on local IP list. 
            foreach (var device in devices.Where(x => !LocalIPList.Contains(x.Address.ToString())))
            {
                var services = new Scanner(new Target(device.Address)).ServiceDiscovery();

                if (services.FirstOrDefault().Ports.Count() > 0) 
                {
                    // No reason to audit a device that has no open ports
                    updatedDevices.AddRange(services);
                    Console.WriteLine($"Service scanner has found {services.FirstOrDefault().Ports.Count()} open ports on {device.Address}");
                }
            }
            
            Console.WriteLine($"Service scan completed, {updatedDevices.Count} devices found with open ports.");
            return updatedDevices;
        }

        public List<DeviceModel> VulnerabilityScan(List<Host> devices)
        {
            Console.WriteLine("");
            Console.WriteLine("Vulnerability scan started, please wait...");
            var client = new VulnerabilityClient();
            var vulnerableDevices = client.ScanVulnerabilities(devices);
            
            Console.WriteLine($"Vulnerability scan completed, {vulnerableDevices.Count()} device(s) may have vulnerabilities");
            
            return vulnerableDevices;
        }
    }
}