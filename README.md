# GetNetStat
Home of the `Get-NetStat` replacement for the old `netstat.exe` utility on *Windows*.

## Objectives

The Windows utility `netstat.exe` is very useful to examine connections and ports but it is text-based and OS-specific.

The `Get-NetTCPConnection` cmdlet applies to TCP only, is not available on .NET Core and has no DNS resolution.

That's why I implemented this **PowerShell** module and `Get-NetStat`: it is based on .NET Core, works on *Windows PowerShell* and *PowerShell*, supports TCP and UDP connections, returns rich objects, and features a very fast multi-threaded DNS resolution.

Use the "Discussions" tab to join a discussion if you find issues or have suggestions.

## Cross-Platform Considerations
As [Marc-André Moreau](https://twitter.com/awakecoding) correctly pointed out, this command is limited to *Windows* due to dependencies to *iphlpapi.dll* which is a native *Windows* library. 

If you require a cross-platform solution there currently seems no better way than to wrap the various native commands found on each platform, i.e. [here](https://gist.github.com/awakecoding/14ae283e0018a6e9e77ba23c1f4d26f2).


## Requirements

Requires *PowerShell* version 5.1 or better. Runs on *Windows PowerShell* and *PowerShell 7*. Runs on *Windows*.

## Installation

To install the module, run this:

```powershell
Install-Module -Name GetNetStat -Scope CurrentUser
```

Once the module is installed, you can use the new `Get-NetStat` command:

### View All Connections

```powershell
Get-NetStat
```

```
PS> Get-NetStat

Protocol LocalIp          LocalPort RemoteIp        RemotePort           State   Pid PidName
-------- -------          --------- --------        ----------           -----   --- -------
TCP      0.0.0.0                135 0.0.0.0                  0       Listening  1148 svchost
TCP      0.0.0.0                445 0.0.0.0                  0       Listening     4 System
TCP      0.0.0.0               5040 0.0.0.0                  0       Listening  4932 svchost
TCP      0.0.0.0               5985 0.0.0.0                  0       Listening     4 System
TCP      0.0.0.0               7680 0.0.0.0                  0       Listening  9128 svchost
```

### Outgoing HTTPS: Connections (to port 443)

Add the `-Resolve` parameter to resolve IP addresses and display host names instead:

```powershell
Get-NetStat -RemotePort 443 -Resolve
```

```
Protocol LocalIp          LocalPort RemoteIp        RemotePort           State   Pid PidName
-------- -------          --------- --------        ----------           -----   --- -------
TCP      DELL7390.spe...      49704 lb-140-82-11...        443     Established  9560 chrome
TCP      DELL7390.spe...      49729 server-13-22...        443     Established  9560 chrome
TCP      DELL7390.spe...      49730 server-143-2...        443     Established  9560 chrome
TCP      DELL7390.spe...      49454 51.103.5.186           443     Established  5464 svchost
TCP      DELL7390.spe...      49726 52.113.206.137         443     Established 13736 Teams
TCP      DELL7390.spe...      49742 40.126.1.145           443        TimeWait     0 Idle
```

### Include Origin Information

**NEW in version 1.1.0**

Add the `-IncludeOrigin` switch parameter to look up remote ip addresses and include sophisticated owner information.

This example displays all established connections to https: (port 443) and includes resolved IP addresses and origin information along with the program that maintains the connection:

```powershell
Get-NetStat -RemotePort 443 -State Established -Resolve -IncludeOrigin | Select-Object -Property Origin, RemoteIp, Pid, PidName
```

The result looks similar to this:

```
Origin                       RemoteIp                                   PID PIDName
------                       --------                                   --- -------
AS8068 Microsoft Corporation 1drv.ms                                   8968 WINWORD
AS36459 GitHub, Inc.         lb-140-82-112-26-iad.github.com           9684 chrome
AS36459 GitHub, Inc.         lb-140-82-113-26-iad.github.com           9684 chrome
AS15169 Google LLC           fra24s02-in-f14.1e100.net                 9684 chrome
AS14618 Amazon.com, Inc.     ec2-52-72-44-152.compute-1.amazonaws.com  4372 kited
AS15169 Google LLC           156.247.107.34.bc.googleusercontent.com   4372 kited
AS8075 Microsoft Corporation 51.103.5.159                              5472 svchost
AS8075 Microsoft Corporation 52.113.206.46                             5180 Teams
AS8075 Microsoft Corporation 51.103.5.186                             13632 OneDrive
AS54113 Fastly               185.199.110.154                           9684 chrome
AS54113 Fastly               151.101.12.133                            9684 chrome
AS54113 Fastly               151.101.12.133                            9684 chrome
AS54113 Fastly               151.101.12.133                            9684 chrome
AS54113 Fastly               151.101.12.133                            9684 chrome
AS54113 Fastly               151.101.112.133                           9684 chrome
AS8075 Microsoft Corporation 51.107.59.180                            18124 pwsh
AS8075 Microsoft Corporation 52.137.103.96                            11008 svchost
AS8075 Microsoft Corporation 52.114.133.168                            5180 Teams
AS8075 Microsoft Corporation 51.138.106.75                             7828 svchost
AS8068 Microsoft Corporation 52.113.194.132                            5180 Teams
AS8075 Microsoft Corporation 52.114.74.217                             2748 Teams
```

### List Applications with HTTPS Connections

```powershell
Get-NetStat -RemotePort 443 -TCP | 
Select-Object -Property Pid, PidName | 
Where-Object Pid -gt 0 | 
Sort-Object -Property PidName -Unique
```

```
  PID PIDName
  --- -------
 9560 chrome
12752 OneDrive
 5464 svchost
14204 Teams
```

If you'd like to get the full paths to the applications maintaining HTTPS connections, run the process IDs through `Get-Process`:

```powershell
Get-NetStat -RemotePort 443 -TCP | 
Select-Object -ExpandProperty Pid | 
Foreach-Object { Get-Process -id $_ } | 
Select-Object -ExpandProperty Path | 
Sort-Object -Unique
```

```
C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
C:\Users\tobia\AppData\Local\GitHubDesktop\app-2.6.1\GitHubDesktop.exe
C:\Users\tobia\AppData\Local\Microsoft\OneDrive\OneDrive.exe
C:\Users\tobia\AppData\Local\Microsoft\Teams\current\Teams.exe
```

### Check Port Availability

This example checks whether PowerShell remoting port 5985 is actually listening (checking whether local host has PowerShell remoting enabled):

```powershell
(Get-NetStat -LocalPort 5985).State -eq [NetStat+State]::Listening
```

```
True
```

### Resolve Results From Other Commands

`Resolve-HostNameProperty` is a separate reusable command that uses multi-threading to resolve one or more properties on *any* object.

Here is an example where `Get-NetTcpConnection` returns results. `Resolve-HostNameProperty` takes these results and resolves whatever it finds in the specified property *RemoteAddress* using a maximum of 100 concurrent threads:

```powershell
Get-NetTCPConnection -RemotePort 443 | Resolve-HostNameProperty -Property RemoteAddress -ThrottleLimit 100
```

```
LocalAddress                        LocalPort RemoteAddress                       RemotePort
------------                        --------- -------------                       ----------
192.168.2.105                       65168     lb-140-82-121-5-fra.github.com      443
192.168.2.105                       65158     fra15s29-in-f14.1e100.net           443
192.168.2.105                       65159     fra15s22-in-f3.1e100.net            443
192.168.2.105                       64906     lb-140-82-113-26-iad.github.com     443
192.168.2.105                       65177     51.138.106.75                       443
192.168.2.105                       65172     52.114.20.18                        443
192.168.2.105                       65171     52.114.20.18                        443
```

### Check Applications

Show connections for specific running applications only, i.e. connections maintained by the **Chrome** browser:

```powershell
Get-NetStat -PidName chrome -Resolve
```

```
Protocol LocalIp          LocalPort RemoteIp        RemotePort           State   Pid PidName
-------- -------          --------- --------        ----------           -----   --- -------
TCP      DELL7390.spe...      49704 lb-140-82-11...        443     Established  9560 chrome
TCP      DELL7390.spe...      49696 wb-in-f188.1...       5228     Established  9560 chrome
TCP      DELL7390.spe...      49832 fra16s07-in-...        443     Established  9560 chrome
UDP      0.0.0.0               5353 DELL7390.spe...          0          Closed 14740 chrome
```

### TCP and Resolve

Show TCP-only connections with an *established* connection, and resolve host names:

```powershell
Get-NetStat -State Established -Resolve -TCP
```

```
Protocol LocalIp          LocalPort RemoteIp        RemotePort           State   Pid PidName
-------- -------          --------- --------        ----------           -----   --- -------
TCP      DELL7390.spe...      49696 wb-in-f188.1...       5228     Established  9560 chrome
TCP      DELL7390.spe...      49704 lb-140-82-11...        443     Established  9560 chrome
TCP      DELL7390.spe...      49770 storage3.local        5510     Established  5356 Synology Active Backup...
TCP      DELL7390.spe...      49832 fra16s07-in-...        443     Established  9560 chrome
TCP      DELL7390.spe...      57116 storage3.local        5510     Established  5356 Synology Active Backup...
TCP      DELL7390.spe...      49771 STORAGE3              5510     Established  5356 Synology Active Backup...
TCP      DELL7390.spe...      49772 STORAGE3              5510     Established  5356 Synology Active Backup...
TCP      DELL7390.spe...      49454 51.103.5.186           443     Established  5464 svchost
TCP      DELL7390.spe...      49726 52.113.206.137         443     Established 13736 Teams
```

## Notes

DNS resolution is a particularly expensive and slow task. If you don't need resolved IP addresses, don't resolve. That's why `Get-NetStat` *by default does not* resolve IP addresses.

To resolve IP addresses, add the `-Resolve` parameter.  `Get-NetStat` sports a very fast multi-threaded DNS resolution with up to 80 parallel name resolutions. Even though it is fast, not resolving is faster. Use `-Resolve` wisely.

To make DNS resolution versatile and reusable, it is performed by a separate cmdlet named `Resolve-HostNameProperty`. You can use this command separately to resolve any IP address in any list of objects.

Simply pipe the objects to `Resolve-HostNameProperty`, and specify the names of the properties that need to be resolved.

That's why you can use this with other commands to quickly resolve ip addresses. The following example uses `Get-NetTcpConnection` which does not support ip resolution, and pipes the results to `Resolve-HostNameProperty` asking to resolve the property *RemoteAddress* using 100 parallel threads:

```powershell
Get-NetTCPConnection | Resolve-HostNameProperty -Property RemoteAddress -ThrottleLimit 100
```

In version 1.1.0, a new switch parameter `-IncludeOrigin` was added which adds owner information for remote addresses. This functionality uses a free public webservice to look up IP address owner information:

```powershell
Invoke-RestMethod -Uri 'http://ipinfo.io/51.107.59.180/json'
```

The webservice returns rich ownership information:

```
ip       : 51.107.59.180
city     : Zürich
region   : Zurich
country  : CH
loc      : 47.3667,8.5500
org      : AS8075 Microsoft Corporation
postal   : 8001
timezone : Europe/Zurich
readme   : https://ipinfo.io/missingauth
```

### Credits

This module and all of its code is MIT-licensed so you can use it freely for whatever you want.

Part of this work is based on C# code that is commonly floating around when you search for TCP and UDP connection polling. In fact, I found similar code in so many instances that I couldn't identify anyone specific to credit for it.

I cleaned up and revised the C# code to make it faster and to make it use enumerations instead of string output, then added multi-threaded DNS resolution and wrapped everything up as a cross-platform *PowerShell* module.

If you find areas of improvements, please participate (below), fork, etc. 



## Participate!

If you have additional useful examples or use-cases, or if you find issues, or if you have ideas, please participate in our [discussions](https://github.com/TobiasPSP/GetNetStat/discussions)!



