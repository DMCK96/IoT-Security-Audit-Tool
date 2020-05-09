

 using System;
 using System.Collections.Generic;
 using System.Linq;
 using System.Net;
 using System.Net.Mime;
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
                     ipAddress = hostNameIp.AddressList.FirstOrDefault();
                 }
                 catch
                 {
                     // if exception is thrown by Dns.GetHostEntry() then the hostname was not found or not valid.
                 }
                 
                 // At this point if ipAddress is not null then the hostname was found, otherwise we should try to parse the IP
                 if (ipAddress != null || IPAddress.TryParse(address, out ipAddress))
                 {
                     var results = scanner.HostDiscover(ipAddress.ToString(), true);

                     if (results.Any())
                     {
                         var services = scanner.ServiceScan(results);
                         var vulnerableDevices = scanner.VulnerabilityScan(services);

                         if (vulnerableDevices.Any())
                         {
                             OutputResults(vulnerableDevices);
                         }
                     }
                 }
                 else
                 {
                     Console.WriteLine("");
                     Console.WriteLine("No device has been found with that hostname or IP, please ensure the device is powered on and on the same network.");
                     Console.WriteLine("Press any key to close this tool and try again.");
                     Console.ReadKey();
                     System.Environment.Exit(0);
                 }
             }
             else
             {
                 // We know at this point they chose option 2.
                 var results = scanner.HostDiscover("192.168.137.0", false, "24");

                 if (results.Any())
                 {
                     var services = scanner.ServiceScan(results);
                     var vulnerableDevices = scanner.VulnerabilityScan(services);

                     if (vulnerableDevices.Any())
                     {
                         if (vulnerableDevices.Any(x => Enumerable.Where<VulnerabilityModel>(x.Vulnerabilities, v => v.Port == 22 || v.Port == 23).Any()))
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
                                 
                                 Console.WriteLine("Your device may be vulnerable to bruteforce, would you like to test against this (it may take a few minutes)?");
                                 Console.WriteLine("Please select an option (type the number and press enter):");
                                 Console.WriteLine("1. Yes");
                                 Console.WriteLine("2. No");
                                 bruteforceSelection = Console.ReadLine();

                                 bruteforceCycle = bruteforceCycle + 1;
                             }
                             
                             if (bruteforceSelection == "1")
                             {
                                 var bruteforceClient = new BruteforceController();
                                 
                                 var vulnerableSSHDevices = vulnerableDevices.Where(x =>
                                     x.Vulnerabilities.Any(v => v.Port == 22));
                                 
                                 var vulnerableTelnetDevices = vulnerableDevices.Where(x =>
                                     x.Vulnerabilities.Any(v => v.Port == 23));
                                 
                                 Console.WriteLine("");
                                 Console.WriteLine("--- Bruteforce Module ---");
                                 Console.WriteLine("If you did not know the device IP earlier then this may take a while, please be patient.");
                                 Console.WriteLine("");

                                 if (vulnerableSSHDevices.Any())
                                 {
                                     foreach (var device in vulnerableSSHDevices)
                                     {
                                         var deviceName = device.Hostname != null && device.Hostname != ""
                                             ? device.Hostname
                                             : device.IP;
                                         Console.WriteLine($"Starting SSH bruteforce on {deviceName}, please wait...");
                                         bruteforceClient.BruteforceSSH(device);
                                     }
                                 }
                                 
                                 if (vulnerableTelnetDevices.Any())
                                 {
                                     foreach (var device in vulnerableTelnetDevices)
                                     {
                                         var deviceName = device.Hostname != null && device.Hostname != ""
                                             ? device.Hostname
                                             : device.IP;
                                         Console.WriteLine($"Starting telnet bruteforce on {deviceName}, please wait...");
                                         
                                         bruteforceClient.BruteforceTelnet(device);
                                     }
                                 }
                             }
                         }
                         
                         OutputResults(vulnerableDevices);
                     }
                 }
                 
                 Console.WriteLine("");
                 Console.WriteLine("No devices have been found, please ensure the device is powered on and on the same network.");
                 Console.WriteLine("Press any key to close this tool and try again.");
                 Console.ReadKey();
                 System.Environment.Exit(0);
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
                 Console.WriteLine("Device Details:");
                 Console.WriteLine($"Local IP Address: {device.IP}");
                 Console.WriteLine($"Hostname: {device.Hostname}");
                 Console.WriteLine($"MAC Address: {device.PhysicalAddress}");
                 Console.WriteLine($"Manufacturer: {device.Vendor}");
                 Console.WriteLine("");
                 Console.WriteLine("Vulnerabilities:");

                 int counter = 1;
                             
                 foreach (var vulnerability in device.Vulnerabilities)
                 {
                     Console.WriteLine($"---- Vulnerability ({counter}/{device.Vulnerabilities.Count()}) ----");
                     Console.WriteLine($"Service: {vulnerability.Service}");
                     Console.WriteLine($"Port: {vulnerability.Port}");
                     Console.WriteLine($"Type: {vulnerability.Type}");
                     if (!String.IsNullOrWhiteSpace(vulnerability.CVE)) Console.WriteLine($"CVE: {vulnerability.CVE}");
                     Console.WriteLine($"Source: {vulnerability.Source}");
                     Console.WriteLine($"Details: {vulnerability.Description}");
                     Console.WriteLine("");
                     
                     counter += 1;
                 }
             }
         }
     }
 }