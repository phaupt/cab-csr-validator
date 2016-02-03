<?php
/**
 * @version     1.0.0
 * @package     cab-csr-validator
 * @copyright   Copyright (C) 2012. All rights reserved.
 * @license     Licensed under the Apache License, Version 2.0 or later; see LICENSE.md
 * @author      Swisscom (Schweiz) AG
 */
 
/* Requirements */
/* PHP 5.3.x */
/* PHP Curl, OpenSSL */

// Validator class requirement
require_once(__ROOT__.'/conf/configuration.php');
require_once(__ROOT__.'/helpers/app.php');
require_once(__ROOT__.'/helpers/tldextract/tldextract.php');
require_once(__ROOT__.'/helpers/whois/WhoisClient.php');
require_once(__ROOT__.'/helpers/whois/Whois.php');
require_once(__ROOT__.'/helpers/whois/IpTools.php');
require_once(__ROOT__.'/helpers/idna-convert/idna_convert.class.php');

use phpWhois\Whois;
use phpWhois\Utils;

class validator_helper {
	
	/* Configuration */
	protected $validator_config;		// Validator configuration

	/* App */
	protected $app;						// App instance

	/* Time out */
	public $timeout;

	/* Request default values */
	protected $san_entries_max;

	/* CSR content */
	protected $csr_content;

	/* CSR certificate values */
	public $csr_subject;
	public $csr_cn;
	public $csr_o;
	public $csr_ou;
	public $csr_st;
	public $csr_l;
	public $csr_s;
	public $csr_c;
	public $csr_email;
	public $csr_phone;
	public $csr_keysize;
	public $csr_sans;
	public $csr_ips;
	public $csr_domains;
	public $whois_errors;
	
	/* File path for openssl output */
	public $file_path;

	/* Openssl output */
	public $openssl_output;
	
	/* Whois */
	protected $whois_response;
	
	/* Blacklist URLs */
	protected $blacklist_urls;
	protected $blacklist_debian_urls;

	/* Response signature */
	public $response_signature_validity;
	public $response_signature_validity_message;

	/* Response logs */
	public $response_checks = array();	// Error message
	public $response_results = array();

	/* Duration */
	public $duration;					// Duration

	/**
	* validator_helper class
	*
	*/

	public function __construct() {

		/* Get the app instance */
		$this->app = new validator_app();

		/* Check the server requirements */
		if (!$this->checkRequirements()) {
			return false;
		}

		/* Set the configuration */
		if (!$this->setConfiguration()) {
			return false;
		}		
	}

	/**
	* Validator check the requirements of the web server
	*
	* @return 	boolean	true on success, false on failure
	*/
	
	private function checkRequirements() {

		if (!extension_loaded('curl')) {
			$this->setTest('Requirements (php_curl)', false, 'PHP <curl> library is not installed!');
			return false;
		}
		
		if (!extension_loaded('openssl')) {
			$this->setTest('Requirements (php_openssl)', false, 'PHP <openssl> library is not installed!');
			return false;
		}
		
		return true;
	}

	/**
	* Validator set the default configuration
	*
	* @return 	boolean	true on success, false on failure
	*/
	
	private function setConfiguration() {
		
		/* New instance of the validator_config class */
		$this->validator_config = new validator_config();
		
		/* Check if the configuraiton is correct */
		if (!$this->checkConfiguration()) {
			return false;
		}
		
		/* Set the default values */

		/* Request default values */
		$this->timeout = $this->validator_config->timeout;
		$this->san_entries_max = $this->validator_config->san_entries_max;
		
		return true;
	}

	/**
	* Validator check the configuration
	*
	* @return 	boolean	true on success, false on failure
	*/
	private function checkConfiguration() {

		if (!strlen($this->validator_config->timeout)) {
			$this->setTest('Configuration (timeout)', false, 'Timeout not defined!');
			return false;
		}

		if (!strlen($this->validator_config->san_entries_max)) {
			$this->setTest('Configuration (san_entries_max)', false, 'Maximum SAN entries not defined!');
			return false;
		}
		
		return true;
	}

	/**
	* Validator, check the CSR
	*
	* @return 	boolean	true on success, false on failure
	*/
	public function checkRequest() {

		/* Calculate the request duration */
		$time_start = microtime(true);

		// Get the CSR content
		$this->setTest($this->app->getText('APP_REQUEST_1'), $this->getCsrContent(), $this->app->getText('APP_ERROR_1'));

		// Check if the CSR is a valid blcok
		$this->setTest($this->app->getText('APP_REQUEST_2'), $this->checkValidBlock(), $this->app->getText('APP_ERROR_2'));
		
		if (!$this->getCsrSubject()) {
			$this->getDuration($time_start);
			return false;
		}

		// Check the key size, should be only 2048 bits
		$this->setTest($this->app->getText('APP_REQUEST_3'), $this->checkKeySize(), $this->app->getText('APP_ERROR_3'));

		// Check the weak debian key
		$this->setTest($this->app->getText('APP_REQUEST_4'), $this->checkWeakDebiankey(), $this->app->getText('APP_ERROR_4'));

		// The Common Name (CN) must be available.
		$this->setTest($this->app->getText('APP_REQUEST_5'), $this->checkCommonNameAvailable(), $this->app->getText('APP_ERROR_5'));

		$san_value = true;

		if (!$this->getCsrSanValues()) {
			$san_value = false;
		}

		// One of the SAN entries must correspond to the common name.
		$this->setTest($this->app->getText('APP_REQUEST_7'), $san_value ? $this->checkSanWithCn() : false, $this->app->getText('APP_ERROR_7'));

		// The field Organization (O) is MANDATORY.
		$this->setTest($this->app->getText('APP_REQUEST_8'), $this->checkOrganisation(), $this->app->getText('APP_ERROR_8'));
		
		// At least ONE of the following fields MUST be present: Locality (L) or State (S). It is allowed to include both.
		$this->setTest($this->app->getText('APP_REQUEST_9'), $this->checkLocalityAndState(), $this->app->getText('APP_ERROR_9'));

		// The field country (C) is MANDATORY.
		$this->setTest($this->app->getText('APP_REQUEST_10'), $this->checkCountry(), $this->app->getText('APP_ERROR_10'));

		// the CSR should not contain any e-mail address.
		$this->setTest($this->app->getText('APP_REQUEST_11'), $this->checkEmail(), $this->app->getText('APP_ERROR_11'));

		// The X.509v3 Extension Subject Alternative Name (SAN) must be available
		$this->setTest($this->app->getText('APP_REQUEST_12'), $this->checkSanAvailable(), $this->app->getText('APP_ERROR_12'));

		// Subject Alternative Name (SAN) must be available and be present only once
		$this->setTest($this->app->getText('APP_REQUEST_21'), $this->checkSanOnce(), $this->app->getText('APP_ERROR_21'));

		// The SAN must contain at least 1 entry and a configurable number of maximal entries.
		$this->setTest($this->app->getText('APP_REQUEST_13'), $san_value ? $this->checkSanEntries() : true, str_replace('%s', $this->san_entries_max, $this->app->getText('APP_ERROR_13')));

		// Subject Alternative Name (SAN) does not contain reserved IPv4 address(es) in the RFC 1918
		$this->setTest($this->app->getText('APP_REQUEST_19'), $san_value ? $this->checkSanReservedIp4() : true, $this->app->getText('APP_ERROR_19'));

		// Subject Alternative Name (SAN) does not contain reserved IPv6 address(es) in the RFC 4153
		$this->setTest($this->app->getText('APP_REQUEST_22'), $san_value ? $this->checkSanReservedIp6() : true, $this->app->getText('APP_ERROR_22'));

		// The SAN's domain(s) must be a valid FQDN/IP address (verifiable through WhoIS lookup).
		$this->setTest($this->app->getText('APP_REQUEST_14'), $san_value ? $this->checkSanWhois() : true, $this->app->getText('APP_ERROR_14').' ['.$this->whois_errors.']');

		$row = array();

		// The domains of the Subject Alternative Name (SAN) entries are not blacklisted.
		$row["check"] = $this->app->getText('APP_REQUEST_16');

		if ($this->checkSanBlacklisted()) {
			$row["result"] = true;
			$row["result_msg"] = $this->app->getText('APP_SUBMIT_CHECK_NOT_BLACKLISTED');
		} else {
			$row["result"] = false;
			$row["result_msg"] = $this->app->getText('APP_SUBMIT_CHECK_BLACKLISTED');
		}

		$this->response_checks[] = $row;

		// Is wildcard present?
		$row["check"] = $this->app->getText('APP_REQUEST_18');
		$row["result"] = true;

		$response = $this->checkWildCard();

		if ($response) {
			$row["result_msg"] = $this->app->getText('APP_SUBMIT_CHECK_PRESENT');
		} else {
			$row["result_msg"] = $this->app->getText('APP_SUBMIT_CHECK_NOT_PRESENT');
		}

		$this->response_checks[] = $row;

		// Wildcard applies to the domain(s)
		if ($response) {
			$this->setTest($this->app->getText('APP_REQUEST_23'), $san_value ? $this->checkWildCardApplyToDomain() : true, $this->app->getText('APP_ERROR_23'));
		}

		// Compliant to CAB Requirements
		$this->setResult($this->app->getText('APP_RESULT_1'), $this->checkCabRequirements(), '', $this->app->getText('APP_TEST_1'));

		// Compliant to CAB EV Requirements
		//$this->setResult($this->app->getText('APP_RESULT_2'), $this->checkCabEvRequirements(), '', $this->app->getText('APP_TEST_2'));

		// Valid for Swisscom SSL Smaragd
		$result = $this->checkSwisscomSslSmaragd();
		$this->setResult($this->app->getText('APP_RESULT_3'), $result["result"], $result["result_msg"], $this->app->getText('APP_TEST_3'));

		// Valid for Swisscom EV SSL Quarz
		//$result = $this->checkSwisscomEvSslQuarz();
		//$this->setResult($this->app->getText('APP_RESULT_4'), $result["result"], $result["result_msg"], $this->app->getText('APP_TEST_4'));
		
		$this->getOpensslOutput();

		// Set the duration of the request
		$this->getDuration($time_start);

		return true;
	}

	/**
	* Get CSR content from the form
	*
	* @return 	string CSR content on success, false on failure
	*/
	private function getCsrContent() {
		
		if (!strlen($_FILES["csr_upload"]["tmp_name"]) && !strlen($_POST["csr_text"])) {
			$this->setTest('CSR content', false, 'Any CSR content found!');
			return false;
		}

		if (strlen($_FILES["csr_upload"]["tmp_name"])) {

			$file = fopen($_FILES["csr_upload"]["tmp_name"], 'r');
			$this->csr_content = fread($file, filesize($_FILES["csr_upload"]["tmp_name"]));
			fclose($file);
			
			if (strlen($this->csr_content)) {
				return true;
			}
		}
		
		$this->csr_content = $_POST["csr_text"];

		if (!strlen($this->csr_content)) {
			$this->setTest('CSR content', false, 'Any CSR content found!');
			return false;
		}
		
		return true;
	}

	/**
	* Check if the csr content is a valid block
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkValidBlock() {

		if (!strlen($this->csr_content)) {
			return false;
		}
		
		if (!openssl_csr_get_subject($this->csr_content)) {
			return false;
		}

		return true;
	}

	/**
	* Get the CSR subject
	*
	* @return 	string CSR content on success, false on failure
	*/
	private function getCsrSubject() {
		
		if (!$this->csr_content) {
			return false;
		}

		$this->csr_subject = openssl_csr_get_subject($this->csr_content);

		if (!$this->csr_subject) {
			return false;
		}

		foreach ($this->csr_subject as $key => $value) {
			switch (strtolower($key)) {
				case 'c':
					$this->csr_c = $value;
					break;

				case 'st':

					if (is_array($value)) {
						$this->csr_st = $value;
					} else {
						$this->csr_st[0] = $value;
					}					

					break;

				case 'l':
					$this->csr_l = $value;
					break;

				case 'o':
					$this->csr_o = $value;
					break;

				case 'ou':
					if (is_array($value)) {
						$this->csr_ou = $value;
					} else {
						$this->csr_ou[0] = $value;
					}
					break;

				case 'cn':
					$this->csr_cn = $value;
					break;

				case 'emailaddress':
				case 'mail':
					$this->csr_email = $value;
					break;
			}
		}

		return true;
	}

	/**
	* Check the key size of the request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkKeySize() {

		$cert_details = openssl_pkey_get_details(openssl_csr_get_public_key($this->csr_content));
		$this->csr_keysize = $cert_details['bits'];
	
		if ($this->csr_keysize != 2048) {
			return false;
		}
		
		return true;
	}

	/**
	* Check for weak Debian key
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkWeakDebiankey() {
		
		if (!file_exists(__ROOT__.'/conf/debian_blacklist.db')) {
			$this->setTest('Requirements (debian_blacklist)', false, 'File debian_blacklist.db not found!');
			return true;
		}

		$cert_details = openssl_pkey_get_details(openssl_csr_get_public_key($this->csr_content));
		
		if (!isset($cert_details['rsa'])) {
			return true;
		}

		// Read the debian black list URLs file
		$handle = fopen(__ROOT__.'/conf/debian_blacklist.db', "r");

		// Weak debian key check
		$bin_modulus = $cert_details['rsa']['n'];

		# blacklist format requires sha1sum of output from "openssl x509 -noout -modulus" including the Modulus= and newline.
		# create the blacklist:
		# https://packages.debian.org/source/squeeze/openssl-blacklist
		# svn co svn://svn.debian.org/pkg-openssl/openssl-blacklist/
		# find openssl-blacklist/trunk/blacklists/ -iname "*.db" -exec cat {} >> unsorted_blacklist.db \;
		# sort -u unsorted_blacklist.db > debian_blacklist.db

		$mod_sha1sum = sha1("Modulus=" . strtoupper(bin2hex($bin_modulus)) . "\n");
		$key_in_blacklist = false;

		while (($buffer = fgets($handle)) !== false) {
			if (strpos($buffer, $mod_sha1sum) !== false) {
				$key_in_blacklist = true;
				break; 
			}
		}
		
		fclose($handle);

		if ($key_in_blacklist == false) {
			return true;
		}

		return false;
	}

	/**
	* Check if the Common Name is available
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkCommonNameAvailable() {

		if (!strlen($this->csr_cn)) {
			return false;
		}
		
		return true;
	}

	/**
	* Check the Organisation of the request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkOrganisation() {
		
		if (!strlen($this->csr_o)) {
			return false;
		}

		return true;
	}

	/**
	* Check the Locality and the State of the request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkLocalityAndState() {

		if (!strlen($this->csr_l.$this->csr_s)) {
			return false;
		}

		return true;
	}

	/**
	* Check the Country of the request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkCountry() {

		if (!strlen($this->csr_c)) {
			return false;
		}

		return true;
	}

	/**
	* Check the Email of the request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkEmail() {

		if (strlen($this->csr_email)) {
			return false;
		}

		return true;
	}

	/**
	* Get openssl request output
	*
	* @return 	boolean true on success, false on failure
	*/
	private function getOpensslOutput() {
		
		if (!strlen($this->file_path)) {
			return false;
		}

		if (!file_put_contents($this->file_path, $this->csr_content)) {
			$this->setTest('Writing CSR content into a file', false, 'Unable to write the file!');
			return false;
		}

		$this->openssl_output = trim(shell_exec("timeout " . $this->timeout . " openssl req -noout -text -in " . $this->file_path));
		
		unlink($this->file_path);

		if (!strlen($this->openssl_output)) {
			return false;
		}

		$this->openssl_output = str_replace(array("\r\n","\n"), '<br />', $this->openssl_output);
		
		return true;
	}

	/**
	* Get the Subject Alternative Name from the request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function getCsrSanValues() {

		$this->file_path = sys_get_temp_dir().'/'.uniqid('csr-').'.csr';
		
		if (!file_put_contents($this->file_path, $this->csr_content)) {
			$this->setTest('Writing CSR content into a file', false, 'Unable to write the file!');
			return false;
		}

		$openssl_csr_output = trim(shell_exec("timeout " . $this->timeout . " openssl req -noout -text -in " . $this->file_path . " | grep -e 'DNS:' -e 'IP:'"));
		
		unlink($this->file_path);

		if (!strlen($openssl_csr_output)) {
			return false;
		}

		$sans = explode(",", $openssl_csr_output);
		
		if (!count($sans)) {
			return false;
		}

		$this->csr_sans = array();
		
		foreach($sans as $san) {
			if (strstr(strtolower($san), 'dns') || strstr(strtolower($san), 'ip')) {
				$explode = explode(':', strtolower($san));
				if (strlen($explode[1])) {
					$this->csr_sans[] = $explode[1];
				}
			}
		}

		if (!$this->getCsrDomainsfromSans()) {
			return false;
		}

		return true;
	}

	/**
	* Get the domains from  the Subject Alternative Name of the request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function getCsrDomainsfromSans() {
		
		if (!count($this->csr_sans)) {
			return false;
		}
		
		$san_dns_temp = '';
		$this->csr_ips = array();
		$this->csr_domains = array();

		foreach($this->csr_sans as $san) {

			$tldextract = tldextract($san);

			if (strlen($tldextract["domain"]) && strlen($tldextract["tld"])) {

				$san_dns = $tldextract["domain"].'.'.$tldextract["tld"];

				if ($san_dns != $san_dns_temp) {
					$this->csr_domains[]["domain"] = $san_dns;
					$san_dns_temp = $san_dns;
				}
			} else {
				$this->csr_ips[]["domain"] = $san;
			}			
		}

		return true;		
	}

	/**
	* Check if the Subject Alternative Name is available
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkSanAvailable() {
		
		if (!count($this->csr_sans)) {
			return false;
		}
		
		return true;
	}

	/**
	* Check the Subject Alternative Name maximum allowed entries
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkSanEntries() {

		// Get almost one entry
		if (!strlen($this->csr_sans[0])) {
			return false;
		}

		// Maximum of SAN reach
		if (count($this->csr_sans) > $this->san_entries_max) {
			return false;
			
		}
		
		return true;
	}

	/**
	* Check the reserved IPv4 addresses
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkSanReservedIp4() {

		// Get almost one entry
		if (!count($this->csr_ips)) {
			return true;
		}

		$check = true;

		foreach($this->csr_ips as $ip) {
			if (filter_var($ip, FILTER_VALIDATE_IP)) {
				if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
					if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE)) {
						$check = false;
						break;
					}
				}
			}
		}
		
		return $check;
	}

	/**
	* Check the reserved IPv6 addresses
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkSanReservedIp6() {

		// Get almost one entry
		if (!count($this->csr_ips)) {
			return true;
		}

		$check = true;

		foreach($this->csr_ips as $ip) {
			if (filter_var($ip, FILTER_VALIDATE_IP)) {
				if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
					if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE)) {
						$check = false;
						break;
					}
				}
			}
		}
		
		return $check;
	}

	/**
	* Check the Subject Alternative Name so that one of them should correspond to the Common Name
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkSanWithCn() {

		// One of the SAN entries must correspond to the common name.
		if (!in_array($this->csr_cn, $this->csr_sans)) {
			return false;			
		}
		
		return true;
	}

	/**
	* Do the Whois of the Subject Alternative Name of the request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkSanWhois() {

		// The SAN must contain at least 1 entry
		if (!count($this->csr_domains) && !count($this->csr_domains)) {
			return false;
		}

		// Internal FQDNs, reserved IP addresses and .local domains are strict forbidden.
		$whois = new Whois();
		
		$check = true;
		$whois_errors = array();
		
		if (count($this->csr_domains)) {
		
			$i = 0;
			$san_dns_array = array();

			foreach($this->csr_domains as $domain) {
				
				$whois_response = $whois->lookup($domain["domain"]);

				if (strtolower($whois_response["regrinfo"]["registered"]) != 'yes') {
					$whois_errors[] = $domain["domain"];
					$check = false;
				}

				$this->csr_domains[$i]["whois"] = $this->formatWhoisRawData($whois_response["rawdata"]);
				
				if (isset($whois_response["regyinfo"]["servers"][0]["server"])) {
					$this->csr_domains[$i]["server"] = $whois_response["regyinfo"]["servers"][0]["server"];
				}
				
				$i++;
			}
		}

		if (count($this->csr_ips)) {
		
			$i = 0;
			$san_ips_array = array();

			foreach($this->csr_ips as $ip) {
				
				$whois_response = $whois->lookup($ip["domain"]);

				if (strtolower($whois_response["regrinfo"]["registered"]) != 'yes') {
					$whois_errors[] = $ip["domain"];
					$check = false;
				}

				$this->csr_ips[$i]["whois"] = $this->formatWhoisRawData($whois_response["rawdata"]);
				
				if (isset($whois_response["regyinfo"]["servers"][0]["server"])) {
					$this->csr_ips[$i]["server"] = $whois_response["regyinfo"]["servers"][0]["server"];
				}
				
				$i++;
			}
		}

		if (count($whois_errors)) {
			$this->whois_errors = implode(',', $whois_errors);
		}

		return $check;
	}
	
	/**
	* Format the Whois result as html
	*
	* @return 	string html code
	*/
	private function formatWhoisRawData($datas) {
		
		if (!count($datas)) {
			return false;
		}
		
		$html = '';

		foreach($datas as $data) {
			$html .= $data.'<br />';
		}
		
		return $html;
	}

	/**
	* Check the Subject Alternative Name should be present only once
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkSanOnce() {

		// The SAN must contain at least 1 entry
		if (!count($this->csr_sans)) {
			return true;
		}

		if (count(array_unique($this->csr_sans)) != count($this->csr_sans)) {
			return false;
		}
		
		return true;
	}

	/**
	* Check if the Subject Alternative Name domains is blacklisted
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkSanBlacklisted() {

		if (!count($this->csr_domains)) {
			return true;
		}

		// Check if the DNS is blacklisted
		$this->getBlackListUrls();

		if (count($this->blacklist_urls)) {
			
			$check = false;

			foreach($this->blacklist_urls as $blacklist_url) {

				if (!trim($blacklist_url)) {
					continue;
				}

				$blacklist_dns = $this->getBlackListDns(trim($blacklist_url));

				foreach($this->csr_domains as $domain) {
					if (in_array($domain["domain"], $blacklist_dns)) {
						$check = true;
						break;
					}
				}
				
				if ($check) {
					break;
				}
			}
			
			if ($check) {
				return false;				
			}
		}

		return true;
	}

	/**
	* Check if a wildcard is present
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkWildCard() {
		
		if (!count($this->csr_sans)) {
			return false;
		}
		
		$check = false;

		foreach($this->csr_sans as $san) {
			if (in_array('*', explode('.', $san))) {
				$check = true;
				break;
			}
		}

		return $check;
	}

	/**
	* Check if a wildcard apply to a valid domain detected
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkWildCardApplyToDomain() {
		
		if (!count($this->csr_sans)) {
			return false;
		}

		// Internal FQDNs, reserved IP addresses and .local domains are strict forbidden.
		$whois = new Whois();

		$check = true;

		foreach($this->csr_sans as $san) {

			if (in_array('*', explode('.', $san))) {
				
				if (strlen($wildcard = strstr($san, '*', true))) {
					$check = false;
					break;
				}

				$tldextract = tldextract($san);
				
				if (strlen($tldextract["domain"]) && strlen($tldextract["tld"])) {	

					$whois_response = $whois->lookup($tldextract["domain"].'.'.$tldextract["tld"]);

					if (strtolower($whois_response["regrinfo"]["registered"]) != 'yes') {
						$check = false;
						break;
					}
				} else {
					$check = false;
					break;					
				}
			}
		}

		return $check;
	}

	/**
	* Check the CAB EV requirements
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkCabRequirements() {
		
		$return = true;
		
		foreach($this->response_checks as $check) {
			if (in_array(false, $check)) {
				$return = false;
				break;
			}
		}
		
		return $return;
	}

	/**
	* Check the CAB EV requirements
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkCabEvRequirements() {

		if (!$this->checkCabRequirements()) {
			return false;
		}

		if (in_array('*', $this->csr_sans)) {
			return false;
		}
		
		return true;
	}

	/**
	* Check the Swisscom SSL Smaragd
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkSwisscomSslSmaragd() {
		
		$result = array();

		if (!$this->checkCabRequirements()) {
			$result["result"] = false;
			$result["result_msg"] = false;
			return $result;
		}
		
		$result["result"] = true;
		$result["result_msg"] = $this->app->getText('APP_SUBMIT_CHECK_YES');
		
		if ($this->checkWildCard()) {
			$result["result_msg"] .= ', '.$this->app->getText('APP_SUBMIT_CHECK_WILDCARD');
		} else {
			$result["result_msg"] .= ', '.$this->app->getText('APP_SUBMIT_CHECK_NO_WILDCARD');			
		}
		
		$result["result_msg"] .= ' '.str_replace('%s', count($this->csr_domains), $this->app->getText('APP_SUBMIT_CHECK_DOMAINS'));
		
		return $result;
	}

	/**
	* Check the Swisscom EV SSL Quarz
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkSwisscomEvSslQuarz() {

		$result = array();

		if (!$this->checkCabEvRequirements()) {
			$result["result"] = false;
			return $result;
		}
		
		$result["result"] = true;

		$result["result_msg"] = $this->app->getText('APP_SUBMIT_CHECK_YES');
		
		if (in_array('*', $this->csr_sans)) {
			$result["result_msg"] .= ', '.$this->app->getText('APP_SUBMIT_CHECK_WILDCARD');
		} else {
			$result["result_msg"] .= ', '.$this->app->getText('APP_SUBMIT_CHECK_NO_WILDCARD');			
		}
		
		$result["result_msg"] .= ' '.str_replace('%s', count($this->csr_domains), $this->app->getText('APP_SUBMIT_CHECK_DOMAINS'));
		
		return $result;		
	}

	/**
	* Get the blacklist of DNSs
	*
	* @return 	array of DNSs on success, false on failure
	*/
	private function getBlackListDns($blacklist_url) {
		
		if (!strlen($blacklist_url)) {
			return false;
		}

		// Initiate CURL POST call
		$ch = curl_init();
		
		// Set Curl options
		curl_setopt($ch, CURLOPT_URL, $blacklist_url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
		curl_setopt($ch, CURLOPT_TIMEOUT, 60);    
		
		// Send the request
		$blacklist_dns = curl_exec($ch);

		curl_close($ch);
		
		return preg_split('/$\R?^/m', $blacklist_dns);		
	}

	/**
	* Get the blacklist of URLs
	*
	* @return 	array of URLs on success, false on failure
	*/
	private function getBlackListUrls() {
		
		if (!file_exists(__ROOT__.'/conf/dns_blacklist.db')) {
			$this->setTest('Requirements (dns_blacklist)', false, 'File dns_blacklist.db not found!');
			return false;
		}

		// Read the black list URLs file and set it in a array
		$handle = fopen(__ROOT__.'/conf/dns_blacklist.db', "r");

		if ($handle) {

			$this->blacklist_urls = array();
			
			while (!feof($handle)) {
				$buffer = fgets($handle, 4096);
				$this->blacklist_urls[] = $buffer;
			}

			fclose($handle);
		}		

		return true;
	}

	/**
	* Get the duration of the tests execution
	*
	* @return 	string CSR content on success, false on failure
	*/
	private function getDuration($time_start) {
		
		if (!$time_start) {
			return false;
		}

		/* Calculate the request duration */
		$time_end = microtime(true);

		/* Calculate the request duration */
		$this->duration = $time_end - $time_start;		
	}

	/**
	* Validator set the test result
	*
    * @param 	string 	$check, test label
    * @param 	boolean	$result, test result
    * @param 	string	$detail, result detail
	* @return 	boolean	true on success, false on failure
	*/
	private function setTest($check, $result = false, $detail = '') {
		
		if (!strlen($check)) {
			return false;
		}
		
		$row = array();
		$row["check"] = $check;
		$row["result"] = $result;
		$row["result_msg"] = $this->app->getText('APP_SUBMIT_CHECK_PASSED');
		
		if (!$result) {
			$row["result_msg"] = $this->app->getText('APP_SUBMIT_CHECK_FAILED');
			$row["detail"] = $detail;
		}

		$this->response_checks[] = $row;
		
		return true;
	}

	/**
	* Validator set the result
	*
    * @param 	string 	$check, test label
    * @param 	boolean	$result, test result
    * @param 	string	$result_msg, result message
    * @param 	string	$detail, result detail
	* @return 	boolean	true on success, false on failure
	*/
	private function setResult($check, $result = false, $result_msg = '', $detail = '') {
		
		if (!strlen($check)) {
			return false;
		}
		
		$row = array();
		$row["check"] = $check;
		$row["result"] = $result;
		
		if (!strlen($result_msg)) {
			$row["result_msg"] = $this->app->getText('APP_SUBMIT_CHECK_YES');
		} else {
			$row["result_msg"] = $result_msg;
		}
		
		if (!$result) {
			$row["result_msg"] = $this->app->getText('APP_SUBMIT_CHECK_NO');
			$row["detail"] = $detail;
		}

		$this->response_results[] = $row;
		
		return true;
	}
}
?>
