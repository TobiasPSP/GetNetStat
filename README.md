# GetNetStat
Home of the cross-plat  Get-NetStat replacement for the old netstat.exe utility on Windows

## Objectives

The Windows utility netstat.exe is very useful to examine connections and ports but it is text-based and OS-specific.

The cmdlet `Get-NetTCPConnection` applies to TCP only, is not available on .NET Core and has no DNS resolution.

That's why I implemented this module and `Get-NetStat`: it is based on .NET Core and cross-platform, supports TCP and UDP connections, returns rich objects, and features a very fast multi-threaded DNS resolution.

Use the tab "Discussion" to join a discussion if you find issues or have suggestions.
