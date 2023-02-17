PS> winget search microsoft.powershell
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe> -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
>>> python
>>> import os
>>> import sys

# https://aka.ms/microsoft-store-terms-of-transaction
