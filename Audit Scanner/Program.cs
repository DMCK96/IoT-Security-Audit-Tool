using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Net.Sockets;
using Audit_Scanner.Controllers.Vulnerability;
using Audit_Scanner.Models;
using Audit_Scanner.Network;
using Audit_Scanner.Vulnerability.Models;
using SaltwaterTaffy.Container;

namespace Audit_Scanner
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            String selection = "";
            int cycle = 0;
            var scanner = new AuditScanner();

            while (selection != "1" && selection != "2")
            {
                if (cycle > 0)
                {
                    Console.WriteLine("You chose an invalid option, please type 1 or 2");
                    Console.WriteLine("");
                }

                Console.WriteLine("Please select an option (type the number and press enter):");
                Console.WriteLine("1. I know the host IP or Hostname");
                Console.WriteLine("2. I do not know the host IP or Hostname");
                selection = Console.ReadLine();

                cycle = cycle + 1;
            }

            if (selection == "1")
            {
                Console.WriteLine("");
                Console.WriteLine("Please input the IP of the local device to be scanned:");
                var address = Console.ReadLine();

                IPAddress ipAddress = null;


                try
                {
                    var hostNameIp = Dns.GetHostEntry(address);
                    ipAddress = hostNameIp.AddressList.Where(x => x.AddressFamily == AddressFamily.InterNetwork)
                        .FirstOrDefault();
                }
                catch
                {
                    // if exception is thrown by Dns.GetHostEntry() then the hostname was not found or not valid.
                }

                // At this point if ipAddress is not null then the hostname was found, otherwise we should try to parse the IP
                if (ipAddress != null || IPAddress.TryParse(address, out ipAddress))
                {
                    var results = scanner.HostDiscover(true, ipAddress.ToString());

                    if (results.Any())
                    {
                        var services = scanner.ServiceScan(results);
                        var vulnerableDevices = scanner.VulnerabilityScan(services);

                        if (vulnerableDevices.Any())
                        {
                            BruteforceModule(vulnerableDevices);
                            OutputResults(vulnerableDevices);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("");
                    Console.WriteLine(
                        "No device has been found with that hostname or IP, please ensure the device is powered on and on the same network.");
                    Console.WriteLine("Press any key to close this tool and try again.");
                    Console.ReadKey();
                    System.Environment.Exit(0);
                }
            }
            else
            {
                // We know at this point they chose option 2.
                var results = scanner.HostDiscover(false);

                if (results.Any())
                {
                    var services = scanner.ServiceScan(results);
                    var vulnerableDevices = scanner.VulnerabilityScan(services);

                    if (vulnerableDevices.Any())
                    {
                        BruteforceModule(vulnerableDevices);
                        OutputResults(vulnerableDevices);
                    }
                }

                Console.WriteLine("");
                Console.WriteLine(
                    "No devices have been found, please ensure the device is powered on and on the same network.");
                Console.WriteLine("Press any key to close this tool and try again.");
                Console.ReadKey();
                System.Environment.Exit(0);
            }
        }

        private static void BruteforceModule(List<DeviceModel> vulnerableDevices)
        {
            if (vulnerableDevices.Any(p => p.OpenPorts.Contains(22) || p.OpenPorts.Contains(23)))
            {
                var bruteforceSelection = "";
                var bruteforceCycle = 0;

                while (bruteforceSelection != "1" && bruteforceSelection != "2")
                {
                    if (bruteforceCycle > 0)
                    {
                        Console.WriteLine("You chose an invalid option, please type 1 or 2");
                        Console.WriteLine("");
                    }

                    Console.WriteLine("");
                    Console.WriteLine(
                        "Your device may be vulnerable to bruteforce, would you like to test against this (it may take a few minutes)?");
                    Console.WriteLine("Please select an option (type the number and press enter):");
                    Console.WriteLine("1. Yes");
                    Console.WriteLine("2. No");
                    bruteforceSelection = Console.ReadLine();

                    bruteforceCycle = bruteforceCycle + 1;
                }

                if (bruteforceSelection == "1")
                {
                    var bruteforceClient = new BruteforceController();

                    var vulnerableSSHDevices = vulnerableDevices.Where(p => p.OpenPorts.Contains(22));
                    var vulnerableTelnetDevices = vulnerableDevices.Where(p => p.OpenPorts.Contains(23));

                    Console.WriteLine("");
                    Console.WriteLine("--- Bruteforce Module ---");
                    Console.WriteLine(
                        "If you did not know the device IP earlier then this may take a while, please be patient.");
                    Console.WriteLine("");

                    if (vulnerableSSHDevices.Any())
                    {
                        foreach (var device in vulnerableSSHDevices)
                        {
                            var deviceName = device.Hostname == null || device.Hostname == "" ||
                                             device.Hostname.ToLower() == "hostname not found."
                                ? device.IP
                                : device.Hostname;
                            Console.WriteLine($"Starting SSH bruteforce on {deviceName}, please wait...");

                            bruteforceClient.BruteforceSSH(device);
                            Console.WriteLine("");
                        }
                    }

                    if (vulnerableTelnetDevices.Any())
                    {
                        foreach (var device in vulnerableTelnetDevices)
                        {
                            var deviceName = device.Hostname == null || device.Hostname == "" ||
                                             device.Hostname.ToLower() == "hostname not found."
                                ? device.IP
                                : device.Hostname;
                            Console.WriteLine($"Starting telnet bruteforce on {deviceName}, please wait...");

                            bruteforceClient.BruteforceTelnet(device);
                            Console.WriteLine("");
                        }
                    }
                }
            }
        }

        private static void OutputResults(List<DeviceModel> vulnerableDevices)
        {
            Console.WriteLine("");
            Console.WriteLine("Potential vulnerabilities have been found in your devices!");
            Console.WriteLine("Displaying most recent vulnerabilities (maximum 5):");
            Console.WriteLine("");

            foreach (var device in vulnerableDevices)
            {
                Console.WriteLine("----------------------------------------------------");
                Console.WriteLine("Device Details:");
                Console.WriteLine($"Local IP Address: {device.IP}");
                Console.WriteLine($"Hostname: {device.Hostname}");
                Console.WriteLine($"MAC Address: {device.PhysicalAddress}");
                Console.WriteLine($"Manufacturer: {device.Vendor}");
                Console.WriteLine("");
                Console.WriteLine($"Total Vulnerabilities: {device.Vulnerabilities.Where(x => x.Date.HasValue).Count()}");

                int counter = 1;

                foreach (var port in device.OpenPorts)
                {
                    var vulnerabilities = device.Vulnerabilities.Where(p => port == p.Port && p.Date.HasValue)
                        .OrderByDescending(x => x.Date.Value).ToList();
                    
                    if (vulnerabilities.Any())
                    {
                        Console.WriteLine($"---- Vulnerabilities for {vulnerabilities.FirstOrDefault().Service} ----");
                        Console.WriteLine(
                            $"This service has {vulnerabilities.Count()} vulnerabilities, details of the latest vulnerabilities displayed below.");
                        Console.WriteLine($"Port: {vulnerabilities.FirstOrDefault().Port}");
                        Console.WriteLine($"Type: {vulnerabilities.FirstOrDefault().Type}");
                        if (!String.IsNullOrWhiteSpace(vulnerabilities.FirstOrDefault().CVE))
                            Console.WriteLine($"CVE: {vulnerabilities.FirstOrDefault().CVE}");
                        Console.WriteLine($"Source: {vulnerabilities.FirstOrDefault().Source}");
                        Console.WriteLine($"Details: {vulnerabilities.FirstOrDefault().Description}");
                        Console.WriteLine("");
                    }

                    counter += 1;
                }

                Console.WriteLine("");
                Console.WriteLine("----------------------------------------------------");
                Console.WriteLine("");
                Console.WriteLine("");
            }
            
            Console.WriteLine("Security audit complete, the results can be seen above.");
            Console.WriteLine("");
            Console.WriteLine("Press any key to close this tool.");
            Console.ReadKey();
            System.Environment.Exit(0);
        }
    }
}