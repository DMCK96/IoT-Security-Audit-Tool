

 using System;
 using System.Collections.Generic;
 using System.Linq;
 using System.Net;
 using Audit_Scanner.Controllers.Vulnerability;
 using Audit_Scanner.Network;
 using Audit_Scanner.Vulnerability.Models;
 using SaltwaterTaffy.Container;

 namespace Audit_Scanner
 {
     internal class Program
     {
         public static void Main(string[] args)
         {
             var bruteforceClient = new BruteforceController();
             bruteforceClient.BruteforceTelnet();
             
             String selection = "";
             var scanner = new AuditScanner();
             
             while (selection != "1" && selection != "2")
             {
                 Console.WriteLine("You chose an invalid option, please type 1 or 2");
                 Console.WriteLine("");
                 Console.WriteLine("Please select an option:");
                 Console.WriteLine("1. I know the host IP");
                 Console.WriteLine("2. I do not know the host IP");
                 selection = Console.ReadLine();
             }

             if (selection == "1")
             {
                 Console.WriteLine("");
                 Console.WriteLine("Please input the IP of the local device to be scanned:");
                 var address = Console.ReadLine();

                 IPAddress ipAddress;
                 
                 if (IPAddress.TryParse(address, out ipAddress))
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
                     //TODO placeholder / wrap in While loop
                     Console.WriteLine("");
                     Console.WriteLine("Please input a valid IP:");
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
                         OutputResults(vulnerableDevices);
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