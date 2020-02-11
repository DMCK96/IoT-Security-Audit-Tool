

 using System;
 using System.Collections.Generic;
 using Audit_Scanner.Network;
 using Audit_Scanner.Network.Models;

 namespace Audit_Scanner
 {
     internal class Program
     {
         public static void Main(string[] args)
         {
             String selection = "";
             var scanner = new Scanner();
             
             while (selection != "1" || selection != "2")
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

                 var singleDevice = new DeviceModel
                 {
                     Address = address
                 };
                 
                 var devices = new List<DeviceModel>();
                 devices.Add(singleDevice);

                 var results = scanner.VulnerabilityScan(devices);
             }
         }
     }
 }