

 using System;
 using System.Collections.Generic;
 using System.Linq;
 using System.Net;
 using Audit_Scanner.Network;

 namespace Audit_Scanner
 {
     internal class Program
     {
         public static void Main(string[] args)
         {
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

                     var vulnerabilities = scanner.VulnerabilityScan(results);
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
                     var cve = scanner.CveScan(services);
                     var vulnerableDevices = scanner.VulnerabilityScan(results);
                 }
                 //TODO host discovery
             }
         }
     }
 }