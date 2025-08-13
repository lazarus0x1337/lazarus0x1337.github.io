---
layout: post
title: 'business logic vulnerabilities: Email address parser discrepancies'
date: 2025-08-14
categories: [docs]
tag: [logic bugs,logic,vulnerabilities,usiness logic vulnerabilities]
---

##  Introduction
While learning about business logic vulnerabilities in PortSwigger’s labs, I came across an interesting exploit: bypassing access controls by manipulating email parsers. This bug fascinated me because it shows how small inconsistencies in how systems parse email addresses can lead to serious security flaws.

In this post, I’ll break down how this vulnerability works, demonstrate it with a simple PortSwigger lab example, and explain its real-world impact. By the end, you’ll understand why email parsing discrepancies matter and how attackers can exploit them to gain unauthorized access.

