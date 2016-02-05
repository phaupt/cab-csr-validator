# cab-csr-validator
CA/Browser Forum CSR Validator

## Requirements
* Openssl
* PHP 5.3.x
* PHP Curl
* PHP Openssl

## Install

### Deploy on a web server

Download the package and make it available to your web server.
Example: `git clone <URL> /var/www/csr_validator`

### Deploy on Swisscom App Cloud
Refer to http://docs.developer.swisscom.com/apps/buildpacks/php/

* Sign-up or Login on https://developer.swisscom.com
* Prepare the target (Orgs, Spaces, Apps)
* Checkout the package like for local deployment on a web server
* Upload the package
```
cd <location of the git checkout>
cf login -a https://api.lyra-836.appcloud.swisscom.com -u yourmail@acme.org
cf target -o ENT-BD-AEN -s prod
cf push cab-csr-validator
```
The related configurations can be found in `manifest.yml` and in the `.bp-config/options.json`

## Configuration
* Rename the configuration file example from `conf/configuration.example.php` to `conf/configuration.php`
* Edit the configuration file `conf/configuration.php` according to your environment

## TLD extract from SANs 
This helper use the PHP TLDExtract Library. More infos here http://w-shadow.com/blog/2012/08/28/tldextract/

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
