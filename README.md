## GoLang implementation of the Live Kernel Dumper with UserSpace Memory

The goal of this project is to dump the Live Kernel Memory with the UserSpace memory, in order to extract lsass secrets with the mimilib.dll without being blocked by an EDR or an AV software. Now, this program will do the same as a taskmanager but will let you choose your output location of the file.

This is possible from version : **Windows 11 > 22H2**

This is nothing new, only a ported version of the great work of others

# Acknowledgement
Original research and code on this from :  

Grzegorz Tworek @0gtweet  
https://github.com/gtworek/PSBits/blob/master/Misc/New-KernelDump.ps1  

Tweet of Antonio Cocomazzi @splinter_code  
https://x.com/splinter_code/status/1785359393246138555  

Nathan Blondel @slowerzs  
https://github.com/Slowerzs/PPLSystem/  

At the time of writing this, most EDR's don't flag this operation.  

# Resolution of this security issue
A tweet announced that it will be fixed in next version : https://x.com/depletionmode/status/1797887978506977551


# Disclaimer  
This tool is intended solely for academic purposes and must not be utilized for any unlawful activities or any activities that breach ethical guidelines and regulations.

# Standard way to dump with Task Manager  
-Click Details  
-Select process ID 4 SYSTEM  
- Create live kernel memory dump file -> change memory dump settings
  ![taskmanager](./taskmanager1.jpg?raw=true "change memory dump settings")
- Add Capture user page  
  ![taskmanager](./taskmanager2.jpg?raw=true "add Capture user page")
- Dump Full live kernel memory dump  
  ![taskmanager](./taskmanager3.jpg?raw=true "Dump Full live kernel memory dump")
- File will be saved at : C:\Users\<username>\AppData\Local\Microsoft\Windows\TaskManager\LiveKernelDumps\livedump.DMP  



# Build
```
cd kerneldumperwin11
go build -o kerneldumperwin11.exe kerneldumperwin11.go
```

# Build obfuscated
With String obfuscations library Garble
```
go install mvdan.cc/garble@latest
... (your path should contain garble.exe)  
garble -tiny -literals -seed=random build kerneldumperwin11.go
```

# Run on a Win11 machine
![dumping](./dumping1.jpg?raw=true "Dumping on Win11 machines")

# Extract secrets with mimilib.dll with WinDBG on another machine
![extracting creds](./dumping2.JPG?raw=true "Analysing dump file with WinDBG and mimilib.dll")
