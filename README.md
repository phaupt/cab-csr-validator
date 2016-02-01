# cab-csr-validator
CA/Browser Forum CSR Validator

## Requirements
* Openssl
* PHP 5.3.x
* PHP Curl
* PHP Openssl

## Install
Download the package and make it available to your web server.
Example: `git clone <URL> /var/www/csr_validator`

## Configuration
* Rename the configuration file example from `conf/configuration.example.php` to `conf/configuration.php`
* Edit the configuration file `conf/configuration.php` according to your environment

## Test Whois
This helper use the PHP Whois Library. More infos here https://github.com/phpWhois/phpWhois

## Test Domain Blacklisted
The helper will read this file `conf/dns_blacklist.db`. It will then open all URLs configured on this file and then compare with all DNS of the CSR.
To add more blacklisted domain, create a file with all blacklisted DNS and set the path (file or http path) on the `dns_blacklist.db` file.

## Test Internal IPs
The helper use the `filter_var()` PHP function, http://php.net/manual/fr/function.filter-var.php, using FILTER_VALIDATE_IP, FILTER_FLAG_IPV4, FILTER_FLAG_IPV6, FILTER_FLAG_NO_PRIV_RANGE filters.

## Test Debian Weak Keys
Blacklist format requires sha1sum of output from "openssl x509 -noout -modulus" including the Modulus= and newline.
Create the blacklist:
* https://packages.debian.org/source/squeeze/openssl-blacklist
* svn co svn://svn.debian.org/pkg-openssl/openssl-blacklist/
* find openssl-blacklist/trunk/blacklists/ -iname "*.db" -exec cat {} >> unsorted_blacklist.db \;
* sort -u unsorted_blacklist.db > debian_blacklist.db
