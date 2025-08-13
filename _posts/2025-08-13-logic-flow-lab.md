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
### Unicode overflows
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

