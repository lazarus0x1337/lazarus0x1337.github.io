---
layout: post
title: 'business logic vulnerabilities: Email address parser discrepancies'
date: 2025-08-13
categories: [docs]
tag: [logic bugs,logic,vulnerabilities,business logic vulnerabilities]
---

## 1. Introduction
While learning about business logic vulnerabilities in PortSwigger’s labs, I came across an interesting exploit: bypassing access controls by manipulating email parsers. This bug fascinated me because it shows how small inconsistencies in how systems parse email addresses can lead to serious security flaws.

In this post, I’ll break down how this vulnerability works, demonstrate it with a simple PortSwigger lab example, and explain its real-world impact. By the end, you’ll understand why email parsing discrepancies matter and how attackers can exploit them to gain unauthorized access.

## 2. Parser discrepancies
### 2.1 Unicode overflows
Many security systems block special characters (like @, ', ", or ;) in email fields to prevent injection attacks. 
attackers can bypass these filters by using Unicode characters that overflow into blocked ASCII characters when parsed.
#### example :
Some programming languages (like PHP’s chr()) normalize Unicode code points into the 0-255 range using a modulo 256 operation, effectively converting high Unicode values into standard ASCII.
```php
chr(0x100 + 0x40) → chr(256 + 64) → chr(64) → '@'
```
```bash
examples : 
'✨' === '('
'✩' === ')'
'✻' === ';'
'✼' === '<'
'✽' === '='
'✾' === '>'
'❀' === '@'
```
#### Conclusion
Unicode overflows expose a critical flaw: security filters often check for literal characters but miss their Unicode-encoded equivalents. Attackers exploit this by submitting high-code-point characters that normalize into blocked symbols (@, ', etc.), bypassing access controls.

### 2.2 Encoded-word
The encoded-word syntax from [RFC 2047](https://www.rfc-editor.org/rfc/rfc2047.html) is primarily used in email headers (Subject, From, To) to encode non-ASCII characters. 

If we use an encoded email as an example illustration from whitepaper by Gareth Heyes:
![how-encoded-word-works](/assets/how-encoded-word-works.png "how-encoded-word-works")

- The "=?" indicates the start of an encoded-word .
- Specify the charset in this case UTF-8 .
-  two '?' for type of encoding :  Q-Encoding -> `?q?`
-  Q-Encoding is simply hex with an equal prefix `=41=42=43` === `ABC` .
-  ?= indicates the end of the encoding .


#### Methodology/Tooling
![methodology](/assets/methodology.png "methodology")

let's talk about charset :
 - we can the charset "x" to reduce the size of the probe but some systems reject unknown charsets and would fail.
#### GitHub Email Parser Exploit Bypassing Cloudflare Zero Trust (just using unknow charsets)
A critical vulnerability in GitHub's email verification allowed attackers to bypass Cloudflare Zero Trust by exploiting RFC 2047 "encoded-word" parsing. 
By crafting a malicious email with:
```bash
=40 (encoded @) to split domains
=3e (encoded >) to terminate SMTP commands
=00 (null byte) to truncate validation 
```
Root Cause:
GitHub's Ruby-based parser : Decoded encoded-word but failed to sanitize control chars and Processed the null-byte payload
![exploiting-github-email-verification](/assets/exploiting-github-email-verification.png "exploiting-github-email-verification")
Proof of Concept (PoC) by Researcher Gareth Heyes
Security researcher Gareth Heyes successfully demonstrated how to verify unauthorized email domains on GitHub, including:
microsoft.com, mozilla.com, github.com ...
![github-verified-email](/assets/github-verified-emails.png "github-verified-email")

 - charset "UTF-7", "UTF-8" 
#### example about UTF-7
```Ruby’s Mail Gem``` (508M+ downloads)
Auto-decoded UTF-7 in emails, enabling email parser bypasses.
Allowed attackers to hide malicious chars in seemingly "safe" input.
![changing-the-charset-utf-7](/assets/changing-the-charset-utf-7.png "changing-the-charset-utf-7")

 - charset "iso-8859-1"
#### ISO-8859-1 Exploit in GitLab Enterprise Servers
GitLab’s parser auto-decoded ISO-8859-1 but failed to normalize the output, allowing control characters to slip through.
It's very similar to the Github exploit but it required a valid charset and needed space not null. In the diagram I used "x" but in a real attack you'd use "iso-8859-1".
Unlike GitHub’s null-byte trick, this relied on spaces/underscores to confuse validation.
![gitlab-email-verification](/assets/gitlab-email-verification.png "gitlab-email-verification")
Impact:
Unauthorized access to GitLab Enterprise instances using domain whitelisting.
IdP compromise when GitLab served as an identity provider.

## 3. Hands-On Practice in portswigger lab 
### Bypassing Access Controls via Email Address Parsing Discrepancies :
To access admin panel must have a email with domain ginandjuice.shop :
![adminpanel-lab](/assets/adminpanel-lab.png "adminpanel-lab")

#### Investigate encoding discrepancies :
I test charset "x" (unknown charsets) , charset "iso-8859-1" and also utf-8 :
I Notice that the registration is blocked with the error: "Registration blocked for security reasons."
![test1](/assets/test1.png "test1")
```bash
=?x?q?=61=62=63?=test@ginandjuice.shop
=?iso-8859-1?q?=61=62=63?=test@ginandjuice.shop.
=?utf-8?q?=61=62=63?=test@ginandjuice.shop
```
but when i test charset "utf-7" its work fine :

```bash
=?utf-7?q?&AGYAbwBvAGIAYQBy-?=@ginandjuice.shop
(UTF-7 encoded "foobar" -> foobar@ginandjuice.shop)
```
![poctest-utf-7](/assets/poctest-utf-7.png "poctest-utf-7")
now we can use it to craft an attack that tricks the server into sending a confirmation email to your exploit server email address while appearing to still satisfy the ginandjuice.shop domain requirement.
```sh
@ -> &AEA-
Space -> &ACA-
Null -> &AAA-
Underscore -> &AF8-
```
Through extensive testing, I found that encoding spaces was the most effective approach for forcing parser inconsistencies.
```bash
=?utf-7?q?attacker&AEA-myemail.net&ACA-?=@ginandjuice.shop
(result: =?utf-7?q?attacker@myemail.net ?=@ginandjuice.shop)
```
![poc1](/assets/poc1.png "poc1")
In Email client, i get a registration validation email. This is because the encoded email address has passed validation due to the @ginandjuice.shop portion at the end, but the email server has interpreted the registration email as attacker@myemail.com
![poc2](/assets/poc2.png "poc2")


### Automate exploitation of encoded-word with Turbo Intruder : 
 - first i replace value of email with %s.
 -  script i use for fuzzing : [turbo-intruder-scripts]( https://raw.githubusercontent.com/PortSwigger/splitting-the-email-atom/refs/heads/main/tools/turbo-intruder-scripts/encoded-word.py).
 - If you encounter applications with rate limits, change the REQUEST_SLEEP variable to play nicely with those servers.
 - need to change the validServer variable to your target domain to spoof
 - shouldUrlEncode = True

To use it you just need to change the validServer variable to your target domain to spoof.
and we can easily customise the script to perform other attacks. 
![turbo-intruder](/assets/turbo-intruder.png "turbo-intruder")

If the attack works you should receive a collaborator interaction within Turbo Intruder. This means the email domain is spoofable. 

I sort by words and i get valid responde :
![automation-trubo-email](/assets/automation-trubo-email.png "automation-trubo-email")

## 4. References & Resources
 - Whitepaper by Gareth Heyes of the PortSwigger Research team : [Link](https://portswigger.net/research/splitting-the-email-atom).
 - lab for practice : [Link](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies).
 - tools for fuzzing : [Link](https://github.com/PortSwigger/splitting-the-email-atom/tree/main/tools). 
 - [Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988).
