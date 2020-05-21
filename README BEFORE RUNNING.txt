This folder contains the entire source code for my security audit tool.

This tool has two requirements nmap and .Net Framework 4.8. 

Nmap must be installed and it must have the PATH registered (this is selected by default during installation).

This tool does not have to be ran from an IDE, you may run the application via Audit_Scanner.exe - Shortcut.

Audit Scanner/Resources/Credentials.csv must not be open when the software is running, this will prevent the brute-force module being able to read the file and load the credentials.