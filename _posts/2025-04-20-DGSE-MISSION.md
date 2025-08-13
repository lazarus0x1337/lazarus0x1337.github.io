---
layout: post
title: Secure Nginx with WAF/ModSecurity
date: 2025-03-27
categories: [docs]
tag: [documentation, services, WAF , ModSecurity , WebSecurity , NginxSecurity , CyberSecurity , ApplicationSecurity , OWASP , DDoSProtection , SecureWeb , Firewall , CyberSecurity , DevOps]
---

## Containerizing Nginx with ModSecurity

## 1. Introduction

### What is ModSecurity?
ModSecurity is a free and open-source Web Application Firewall (WAF) that began as an Apache module and has grown into a powerful security tool. It protects web applications by inspecting incoming requests in real time and enforcing predefined security rules to block threats like SQL Injection (`SQLi`) and Cross-Site Scripting (`XSS`).

While it was initially developed for Apache, ModSecurity can also be seamlessly integrated with Nginx, as outlined in this guide.

## 2. Prerequisites
To set up ModSecurity with Nginx in a container, you'll need a Linux-based image as the foundation :
* We use `Debian 12.9` for its stability and package support

Since ModSecurity works as a Web Application Firewall (WAF) for Nginx, you must install and run `Nginx` inside the container.
Additionally, ensuring all required dependencies and libraries are available is essential for a smooth installation.

## 3. Downloading & Building ModSecurity
Before starting this part, it's important to note that ModSecurity is not officially supported as a native Nginx module. However, the modsecurity-nginx connector provides a reliable bridge between Nginx and libmodsecurity, The ModSecurity-nginx connector takes the form of an Nginx module that provides a layer of communication between Nginx and ModSecurity.
For more details, visit the [ModSecurity-nginx GitHub repository](https://github.com/owasp-modsecurity/ModSecurity-nginx).

To begin the installation process
Install all the dependencies required for the build and compilation process with the following command:

`apt install -y git nginx bison build-essential ca-certificates curl dh-autoreconf doxygen flex gawk git iputils-ping libcurl4-gnutls-dev libexpat1-dev libgeoip-dev liblmdb-dev libpcre3-dev libpcre2-dev libssl-dev libtool libxml2 libxml2-dev libyajl-dev locales liblua5.3-dev pkg-config wget zlib1g-dev zlib1g-dev libxslt1-dev libgd-dev libperl-dev systemctl`

this is my dockerfile :
![dockerfile](/assets//dockerfile.png "dockerfile")


I generate an SSL certificate for Nginx using OpenSSL and copies various configuration files into the container :

### First Build Check and Initial Cloning
- Clones the [ModSecurity connector](https://github.com/SpiderLabs/ModSecurity-nginx.git) for Nginx. 
- the main [ModSecurity repository](https://github.com/owasp-modsecurity/ModSecurity.git) from OWASP, which contains the core engine for ModSecurity. 
- the OWASP Core Rule Set (CRS) into a directory named modsecurity-crs. CRS provides a set of generic attack detection rules for ModSecurity. 
- Cloning the Nginx source allows you to recompile it with custom modules.  (replace [1.22.1 with your version of Nginx](https://nginx.org/download/nginx-1.22.1.tar.gz))

### Compiling and Installing ModSecurity
-  Run the following git commands to initialize and update the submodule:
```bash
git submodule init
git submodule update
```
Run the build.sh and configure file, which is responsible for getting all the dependencies for the build process :
```bash
./build.sh
./configure
```
Run the make command to build ModSecurity, After the build process is complete, install ModSecurity :
```bash
    make
    make install
```

### Adding the ModSecurity Module to Nginx 

Display the configure arguments used for your version of Nginx,  example output for Nginx 1.22.1:
```bash
nginx -V
nginx version: nginx/1.22.1
built with OpenSSL 3.3.2 3 Sep 2024 (running with OpenSSL 3.4.1 11 Feb 2025)
TLS SNI support enabled
configure arguments: --with-cc-opt='-g -O2 -Werror=implicit-function-declaration -ffile-prefix-map=/build/reproducible-path/nginx-1.22.1=. -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -fPIC -Wdate-time -D_FORTIFY_SOURCE=2' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -fPIC' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=stderr --lock-path=/var/lock/nginx.lock --pid-path=/run/nginx.pid --modules-path=/usr/lib/nginx/modules --http-client-body-temp-path=/var/lib/nginx/body --http-fastcgi-temp-path=/var/lib/nginx/fastcgi --http-proxy-temp-path=/var/lib/nginx/proxy --http-scgi-temp-path=/var/lib/nginx/scgi --http-uwsgi-temp-path=/var/lib/nginx/uwsgi --with-compat --with-debug --with-pcre-jit --with-http_ssl_module --with-http_stub_status_module --with-http_realip_module --with-http_auth_request_module --with-http_v2_module --with-http_v3_module --with-http_dav_module --with-http_slice_module --with-threads --with-http_addition_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_secure_link_module --with-http_sub_module --with-mail_ssl_module --with-stream_ssl_module --with-stream_ssl_preread_module --with-stream_realip_module --with-http_geoip_module=dynamic --with-http_image_filter_module=dynamic --with-http_perl_module=dynamic --with-http_xslt_module=dynamic --with-mail=dynamic --with-stream=dynamic --with-stream_geoip_module=dynamic
```

To compile the Modsecurity module, copy all of the arguments following configure arguments: from your output of the above command and paste them in place of <Configure Arguments> in the following command:
```bash
sudo ./configure --add-dynamic-module=../ModSecurity-nginx <Configure Arguments>
```

Build the modules with the following command:
```bash
make modules
```
Create a directory for the Modsecurity module  and move the compiled Modsecurity module into your Nginx configuration folder :
```bash
    mkdir /etc/nginx/modules
    cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules
```

### Setting Up OWASP-CRS 

The [OWASP ModSecurity Core Rule](https://github.com/coreruleset/coreruleset) Set (CRS) is a collection of generic detection rules designed for ModSecurity and similar web application firewalls. It provides robust protection against a wide array of attacks—including vulnerabilities listed in the OWASP Top Ten—while keeping false alerts to a minimum. The CRS is effective against various common attack types, such as SQL Injection, Cross-Site Scripting (XSS), and Local File Inclusion (LFI).

To install and configure the OWASP-CRS, follow these steps:

First Clone the OWASP-CRS GitHub repository and rename the crs-setup.conf.example to crs-setup.conf :
```bash
git clone https://github.com/coreruleset/coreruleset modsecurity-crs
mv /opt/modsecurity-crs/crs-setup.conf.example /opt/modsecurity-crs/crs-setup.conf 
```
Rename the default request exclusion rule file:
```bash
mv /opt/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example /opt/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
```
You should now have the OWASP-CRS set up and ready to be used in your Nginx configuration.

### Loading the ModSecurity Module in Nginx 
Add this line in nginx.conf :

```bash 
load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
```
Here is an example portion of an Nginx configuration file that includes the above line:
![loadmodule](/assets/loadmodule.png "loadmodule")

### Configuring Modsecurity
Move the unicode mapping file and the ModSecurity configuration file from your cloned ModSecurity GitHub repository :
```bash
mv /opt/ModSecurity/unicode.mapping /etc/nginx/modsec
mv /conf/modsecurity.conf /etc/nginx/modsec
```

Of course Changing the value of SecRuleEngine to On in the ModSecurity configuration activates the rule engine :
```bash
SecRuleEngine On
```

Adding  also main.conf under the /etc/nginx/modsec directory :
```bash
mv /conf/main.conf /etc/nginx/modsec
cat /etc/nginx/modsec/main.conf
    Include /etc/nginx/modsec/modsecurity.conf
    Include /usr/local/modsecurity-crs/crs-setup.conf
    Include /usr/local/modsecurity-crs/rules/*.conf

```

### Configuring Nginx
insert the following lines in your deffault config file :
```bash
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```
Here is an example configuration file that includes the above lines:
![default](/assets/default.png "default")

## 4. Testing ModSecurity
Below are three examples you can use to test ModSecurity's protection against common attacks:
11. Local File Inclusion (LFI):
This test attempts to include a sensitive file from the server:
```bash
curl -k "https://localhost/index.html?file=../../../../etc/passwd"
```
22. Cross-Site Scripting (XSS):
This test injects a simple JavaScript snippet into a query parameter:
```bash
curl -k "https://localhost/search?q=<script>alert('XSS');</script>"
```
33. SQL Injection (SQLi):
If you have a login page, you can simulate a common SQL injection attempt in the login form:
```bash
curl -k "https://localhost/login?username=admin' OR '1'='1&password=anything"
```
If ModSecurity has been configured correctly and is actively blocking attacks, the following error is returned:

```html
    <html>
    <head><title>403 Forbidden</title></head>
    <body bgcolor="white">
    <center><h1>403 Forbidden</h1></center>
    <hr><center>nginx/1.22.1</center>
    </body>
```

### Conclusion
ModSecurity is a powerful Web Application Firewall that enhances security by detecting and blocking various cyber threats, including SQL Injection, XSS, and LFI attacks. By integrating it with Nginx and properly configuring the OWASP Core Rule Set, you can significantly reduce the risk of web vulnerabilities.

Through testing, we've confirmed that ModSecurity effectively prevents malicious requests, reinforcing its importance in securing web applications. However, security is an ongoing process that requires continuous monitoring and fine-tuning to balance protection and functionality.

I’ve made this configuration available in my repository. You can find the complete setup: [Nginx-Modsecurity](https://github.com/lazarus0x1337/nginx-modsecurity)
