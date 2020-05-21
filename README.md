

## Internet of Things network level security audit tool


This was a tool I created as part of my final year project in Liverpool John Moores University for my project: **Reducing the IoT attack surface with the use of network level security auditing**.

The audience of this tool were those with absolutely no prior security experience so there is an emphasis on keeping the tool as basic for the user as possible.

## Requirements

This tool has two requirements nmap and .Net Framework 4.8. 

Nmap must be installed and it must have the PATH registered (this is selected by default during installation).

IoT-Security-Audit-Tool\Audit Scanner\Resources\Credentials.csv must not be open when the software is running, this will prevent the brute-force module being able to read the file and load the credentials.

Once built the software can be ran from IoT-Security-Audit-Tool\Audit Scanner\bin\Release\Audit_Scanner.exe
