

## Internet of Things network level security audit tool


This was a tool I created as part of my final year project in Liverpool John Moores University for my project: **Reducing the IoT attack surface with the use of network level security auditing**.

The audience of this tool were those with absolutely no prior security experience so there is an emphasis on keeping the tool as basic for the user as possible.

## Requirements

This tool has two requirements nmap and .Net Framework 4.8. 

Nmap download: https://nmap.org/download.html

Nmap must be installed and it **must have the PATH registered (this is selected by default during installation)**. You will quickly get an error from SaltwaterTaffy if this PATH is not set correctly.

IoT-Security-Audit-Tool\Audit Scanner\Resources\Credentials.csv must not be open when the software is running, this will prevent the brute-force module being able to read the file and load the credentials.

Once built the software can be ran from IoT-Security-Audit-Tool\Audit Scanner\bin\Release\Audit_Scanner.exe

## Credit

My software uses a modified version of SaltWater Taffy by Thom Dixon that is available from here: https://github.com/thomdixon/SaltwaterTaffy 

My software also makes use of MinimalisticTelnet by Tom Jannsens available at: https://www.codeproject.com/Articles/19071/Quick-tool-A-minimalistic-Telnet-library
