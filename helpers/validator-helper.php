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

	/* Comodo API */
	protected $api_url;
	protected $timeout = 120;
	protected $showErrorCodes;
	protected $showErrorMessages;
	protected $showFieldNames;
	protected $showEmptyFields;
	protected $showCN;
	protected $showAddress;
	protected $showPublicKey;
	protected $showKeySize;
	protected $showSANDNSNames;
	protected $showCSR;
	protected $showCSRHashes;
	protected $showSignatureAlgorithm;
	protected $countryNameType;

	/* Comodo API response */
	protected $comodo_response_text;
	protected $comodo_response;

	/* Request default values */
	protected $san_entries_max;

	/* CSR content */
	protected $csr_content;
	protected $csr_dns;

	/* CSR certificate values */
	public $csr_cn;
	public $csr_ou;
	public $csr_o;
	public $csr_street1;
	public $csr_street2;
	public $csr_street3;
	public $csr_l;
	public $csr_s;
	public $csr_postalcode;
	public $csr_c;
	public $csr_email;
	public $csr_phone;
	public $csr_keysize;
	public $csr_san;
	
	/* Whois */
	protected $whois_response;
	
	/* Blacklist URLs */
	protected $blacklist_urls;

	/* Response signature */
	public $response_signature_validity;
	public $response_signature_validity_message;

	/* Response error logs */
	public $response_error = false;		// Error, true or false
	public $response_error_type;		// Type of error, warning or error
	public $response_error_message;		// Error message

	/* Duration */
	public $duration;					// Duration


	/**
	* mobileid_helper class
	*
	*/

	public function __construct() {

		/* Check the server requirements */
		if (!$this->checkRequirements()) {
			return false;
		}

		/* Set the configuration */
		if (!$this->setConfiguration()) {
			return false;
		}
		
		$this->app = new validator_app();
	}

	/**
	* Mobileid check the requirements of the web server
	*
	* @return 	boolean	true on success, false on failure
	*/
	
	private function checkRequirements() {

		if (!extension_loaded('curl')) {
			$this->setError('PHP <curl> library is not installed!');
			return false;
		}
		
		return true;
	}

	/**
	* Mobileid set the default configuration
	*
	* @return 	boolean	true on success, false on failure
	*/
	
	private function setConfiguration() {
		
		/* New instance of the mobileID configuration class */
		$this->validator_config = new validator_config();
		
		/* Check if the configuraiton is correct */
		if (!$this->checkConfiguration()) {
			return false;
		}
		
		/* Set the default values */

		/* Set the Comodo API values */
		$this->api_url = $this->validator_config->api_url;
		$this->showErrorCodes = $this->validator_config->showErrorCodes;
		$this->showErrorMessages = $this->validator_config->showErrorMessages;
		$this->showFieldNames = $this->validator_config->showFieldNames;
		$this->showEmptyFields = $this->validator_config->showEmptyFields;
		$this->showCN = $this->validator_config->showCN;
		$this->showAddress = $this->validator_config->showAddress;
		$this->showPublicKey = $this->validator_config->showPublicKey;
		$this->showKeySize = $this->validator_config->showKeySize;
		$this->showSANDNSNames = $this->validator_config->showSANDNSNames;
		$this->showCSR = $this->validator_config->showCSR;
		$this->showCSRHashes = $this->validator_config->showCSRHashes;
		$this->showSignatureAlgorithm = $this->validator_config->showSignatureAlgorithm;
		$this->countryNameType = $this->validator_config->countryNameType;
		
		/* Request default values */
		$this->san_entries_max = $this->validator_config->san_entries_max;
		
		return true;
	}

	/**
	* Mobileid check the configuration
	*
	* @return 	boolean	true on success, false on failure
	*/
	private function checkConfiguration() {

		if (!strlen($this->validator_config->api_url)) {
			$this->setError('Comodo API not defined!');
			return false;
		}

		if (!strlen($this->validator_config->san_entries_max)) {
			$this->setError('Maximum SAN not defined!');
			return false;
		}
		
		return true;
	}

	/**
	* Validateor, check the request certificate
	*
	* @return 	boolean	true on success, false on failure
	*/
	public function checkRequest() {
		
		if (!$this->getCsrContent()) {
			$this->setError($this->app->getText('APP_ERROR_1'));
			return false;
		}

		if (!$this->csrIsAValidBlock()) {
			$this->setError($this->app->getText('APP_ERROR_2'));
			return false;
		}

		/* Calculate the request duration */
		$time_start = microtime(true);
		
		if (!$this->sendRequest()) {
			return false;			
		}
		
		$this->formatCertificate();
		
		//var_dump($this->comodo_response);
		
		if (!$this->checkKeySize()) {
			$this->getDuration($time_start);
			return false;			
		}

		if (!$this->checkCommonName()) {
			$this->getDuration($time_start);
			return false;			
		}

		if (!$this->checkOrganisation()) {
			$this->getDuration($time_start);
			return false;			
		}

		if (!$this->checkLocalityAndState()) {
			$this->getDuration($time_start);
			return false;			
		}

		if (!$this->checkCountry()) {
			$this->getDuration($time_start);
			return false;			
		}

		if (!$this->checkEmail()) {
			$this->getDuration($time_start);
			return false;			
		}

		if (!$this->checkSubjectAlternativeName()) {
			$this->getDuration($time_start);
			return false;			
		}
		
		$this->getDuration($time_start);

		return true;
	}

	/**
	* Get CSR content from the form
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
	* Get CSR content from the form
	*
	* @return 	string CSR content on success, false on failure
	*/
	private function getCsrContent() {
		
		if (!strlen($_FILES["csr_upload"]["tmp_name"]) && !strlen($_POST["csr_text"])) {
			return false;
		}
		
		$file = fopen($_FILES["csr_upload"]["tmp_name"], 'r');
		$this->csr_content = fread($file, filesize($_FILES["csr_upload"]["tmp_name"]));
		fclose($file);
		
		if (strlen($this->csr_content)) {
			return $this->csr_content;
		}
		
		$this->csr_content = $_POST["csr_text"];

		if (!strlen($this->csr_content)) {
			return false;
		}
		
		return true;
	}

	/**
	* Check if the csr content is a valid block
	*
	* @return 	boolean true on success, false on failure
	*/
	private function csrIsAValidBlock() {

		if (!strlen($this->csr_content)) {
			return false;
		}
		
		if (!strpos($this->csr_content, "BEGIN CERTIFICATE REQUEST")) {
			return false;
		}

		if (!strpos($this->csr_content, "END CERTIFICATE REQUEST")) {
			return false;
		}
		
		return true;
	}

	/**
	* Send the CSR request to the Comodo API
	*
	* @return 	boolean true on success, false on failure
	*/
	private function sendRequest() {

		// Get parameters values
		$fields = array('csr' => $this->csr_content,
			'showErrorCodes' => $this->showErrorCodes,
			'showErrorMessages' => $this->showErrorMessages,
			'showFieldNames' => $this->showFieldNames,
			'showEmptyFields' => $this->showEmptyFields,
			'showCN' => $this->showCN,
			'showAddress' => $this->showAddress,
			'showPublicKey' => $this->showPublicKey,
			'showKeySize' => $this->showKeySize,
			'showSANDNSNames' => $this->showSANDNSNames,
			'showCSR' => $this->showCSR,
			'showCSRHashes' => $this->showCSRHashes,
			'showSignatureAlgorithm' => $this->showSignatureAlgorithm,
			'countryNameType' => $this->countryNameType
		);
		
		// URL Encode Values
		$query_string = http_build_query($fields);

		// Initiate CURL POST call
		$ch = curl_init();
		
		// Set Curl options
		curl_setopt($ch, CURLOPT_URL, $this->api_url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
		curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);    
		curl_setopt($ch, CURLOPT_POST, count($fields));
		curl_setopt($ch, CURLOPT_POSTFIELDS, $query_string);
		
		// Send the request
		$this->comodo_response_text = curl_exec($ch);

		curl_close($ch);
		
		return $this->checkResponse();
	}

	/**
	* Check the response of the request to the Comodo API
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkResponse() {
		
		// Check the response from Comodo API
		if (!$this->comodo_response_text) {
			$this->setError($this->app->getText('APP_ERROR_3'));
			return false;
		}
		
		// Split text format response to array
		$this->comodo_response = preg_split('/$\R?^/m', $this->comodo_response_text);
		
		if (!is_array($this->comodo_response) || !count($this->comodo_response)) {
			$this->setError($this->app->getText('APP_ERROR_3'));
			return false;			
		}

		if ($this->comodo_response[0] == '0') {
			return true;
		}

		$this->setError($this->getComodoErrorMessage());

		return false;
	}

	/**
	* Format the value of the certificate request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function formatCertificate() {
		
		// Format the common name
		if (strlen($this->comodo_response[1])) {
			$cn = explode('=', $this->comodo_response[1]);

			if (strlen($cn[1])) {
				$this->csr_cn = $cn[1];
			}
		}

		// Format the organisation unit
		if (strlen($this->comodo_response[2])) {
			$ou = explode('=', $this->comodo_response[2]);

			if (strlen($ou[1])) {
				$this->csr_ou = $ou[1];
			}
		}

		// Format the organisation
		if (strlen($this->comodo_response[3])) {
			$o = explode('=', $this->comodo_response[3]);

			if (strlen($o[1])) {
				$this->csr_o = $o[1];
			}
		}

		// Format the street 1
		if (strlen($this->comodo_response[5])) {
			$s1 = explode('=', $this->comodo_response[5]);

			if (strlen($s1[1])) {
				$this->csr_street1 = $s1[1];
			}
		}

		// Format the street 2
		if (strlen($this->comodo_response[6])) {
			$s2 = explode('=', $this->comodo_response[6]);

			if (strlen($s2[1])) {
				$this->csr_street2 = $s2[1];
			}
		}

		// Format the street 3
		if (strlen($this->comodo_response[7])) {
			$s3 = explode('=', $this->comodo_response[7]);

			if (strlen($s3[1])) {
				$this->csr_street3 = $s3[1];
			}
		}

		// Format the locality
		if (strlen($this->comodo_response[8])) {
			$l = explode('=', $this->comodo_response[8]);

			if (strlen($l[1])) {
				$this->csr_l = $l[1];
			}
		}

		// Format the state
		if (strlen($this->comodo_response[9])) {
			$s = explode('=', $this->comodo_response[9]);

			if (strlen($s[1])) {
				$this->csr_s = $s[1];
			}
		}

		// Format the postal code
		if (strlen($this->comodo_response[10])) {
			$postalcode = explode('=', $this->comodo_response[10]);

			if (strlen($postalcode[1])) {
				$this->csr_postalcode = $postalcode[1];
			}
		}

		// Format the country
		if (strlen($this->comodo_response[11])) {
			$c = explode('=', $this->comodo_response[11]);

			if (strlen($c[1])) {
				$this->csr_c = $c[1];
			}
		}

		// Format the email
		if (strlen($this->comodo_response[12])) {
			$email = explode('=', $this->comodo_response[12]);

			if (strlen($email[1])) {
				$this->csr_email = $email[1];
			}
		}

		// Format the phone
		if (strlen($this->comodo_response[13])) {
			$phone = explode('=', $this->comodo_response[13]);

			if (strlen($phone[1])) {
				$this->csr_phone = $phone[1];
			}
		}

		// Format the key size
		if (strlen($this->comodo_response[15])) {
			$keysize = explode('=', $this->comodo_response[15]);

			if (strlen($keysize[1])) {
				$this->csr_keysize = $keysize[1];
			}
		}

		// Format the Subject Alternative Name
		if (strlen($this->comodo_response[16])) {
			$san = explode('=', $this->comodo_response[16]);

			if (strlen($san[1])) {
				$this->csr_san = $san[1];
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
		
		if (!strlen($this->csr_keysize)) {
			return false;
		}

	
		if ($this->csr_keysize != '2048') {
			$this->setError($this->app->getText('APP_ERROR_4'));
			return false;
		}
		
		// Weak Debian key to be added..
		
		return true;
	}

	/**
	* Check the Common Name of the request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkCommonName() {
		
		if (!strlen($this->csr_cn)) {
			return false;
		}
		
		$dns = explode('.', $this->csr_cn);
		$count = count($dns);
		
		if (!$count) {
			return false;
		}

		$this->csr_dns = $dns[$count-2].'.'.$dns[$count-1];

		$whois = new Whois();

		$this->whois_response = $whois->lookup($this->csr_dns);

		if (strtolower($this->whois_response["regrinfo"]["registered"]) != 'yes') {
			$this->setError($this->app->getText('APP_ERROR_5'));
			return false;
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

				if (in_array($this->csr_dns, $blacklist_dns)) {
					$check = true;
					break;
				}				
			}
			
			if ($check) {
				$this->setError($this->app->getText('APP_ERROR_13'));
				return false;				
			}
		}

		return true;
	}

	/**
	* Get the black list of URLs
	*
	* @return 	array of URLs on success, false on failure
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
	* Get the black list of URLs
	*
	* @return 	array of URLs on success, false on failure
	*/
	private function getBlackListUrls() {
		
		if (!file_exists(__ROOT__.'/conf/blacklist.txt')) {
			$this->setError('Blacklist file does not exist!');
			return false;
		}

		// Read the black list URLs file and set it in a array
		$filename = __ROOT__.'/conf/blacklist.txt';

		$handle = fopen($filename, "r");

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
	* Check the Organisation of the request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkOrganisation() {
		
		if (!strlen($this->csr_o)) {
			$this->setError($this->app->getText('APP_ERROR_6'));
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
			$this->setError($this->app->getText('APP_ERROR_7'));
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
			$this->setError($this->app->getText('APP_ERROR_8'));
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
			$this->setError($this->app->getText('APP_ERROR_15'));
			return false;
		}

		return true;
	}

	/**
	* Check the Subject Alternative Name of the request
	*
	* @return 	boolean true on success, false on failure
	*/
	private function checkSubjectAlternativeName() {

		// The SAN must contain at least 1 entry
		if (!strlen($this->csr_san)) {
			$this->setError($this->app->getText('APP_ERROR_9'));
			return false;
		}
		
		$sans = explode(',', $this->csr_san);

		// Maximum of SAN reach
		if (count($sans) > $this->san_entries_max) {
			$this->setError($this->app->getText('APP_ERROR_10'));
			return false;
			
		}
		
		// One of the SAN entries must correspond to the common name.
		if (!in_array($this->csr_cn, $sans)) {
			$this->setError($this->app->getText('APP_ERROR_11'));
			return false;			
		}

		// Internal FQDNs, reserved IP addresses and .local domains are strict forbidden.
		$whois = new Whois();
		
		$check = true;
		$san_dns_array = array();
		foreach($sans as $san) {

			$dns = explode('.', $san);
			$count = count($dns);

			$san_dns = $dns[$count-2].'.'.$dns[$count-1];
			$san_dns_array[] = $san_dns;
			$whois_response = $whois->lookup($san_dns);

			if (strtolower($whois_response["regrinfo"]["registered"]) != 'yes') {
				$this->setError($this->app->getText('APP_ERROR_12'));
				$check = false;
				break;
			}
		}
		
		if (!$check) {
			return false;
		}

		// Check if the DNS is blacklisted
		/*
		$this->getBlackListUrls();
		
		if (count($this->blacklist_urls) && count($san_dns_array)) {
			
			$check = false;
			foreach($this->blacklist_urls as $blacklist_url) {

				if (!trim($blacklist_url)) {
					continue;
				}

				$blacklist_dns = $this->getBlackListDns(trim($blacklist_url));

				foreach($san_dns_array as $san_dns) {
					if (in_array($san_dns, $blacklist_dns)) {
						$check = true;
						break;
					}
				}
				
				if ($check) {
					break;
				}
			}
			
			if ($check) {
				$this->setError($this->app->getText('APP_ERROR_14'));
				return false;				
			}
		}
		*/

		return true;
	}

	/**
	* Get the error message from Comod API
	*
	* @return 	string Comodo error message
	*/
	private function getComodoErrorMessage() {

		for ($i = 0; $i < (int)$this->comodo_response[0]; $i++) {
			
			switch ($this->comodo_response[$i+1]) {

				case '-1':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_1');
					break;

				case '-2':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_2');
					break;

				case '-3':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_3');
					break;

				case '-4':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_4');
					break;

				case '-5':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_5');
					break;

				case '-6':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_6');
					break;

				case '-7':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_7');
					break;

				case '-8':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_8');
					break;

				case '-10':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_10');
					break;

				case '-11':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_11');
					break;

				case '-12':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_12');
					break;

				case '-13':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_13');
					break;

				case '-14':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_14');
					break;

				case '-18':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_18');
					break;

				case '-19':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_19');
					break;

				case '-23':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_23');
					break;

				case '-24':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_24');
					break;

				case '-25':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_25');
					break;

				case '-40':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_40');
					break;

				case '-41':
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_41');
					break;				

				default:
					$msg = $this->app->getText('APP_ERROR_COMODO_CODE_14');
					break;
			}
		}
		
		return $msg;
	}

	/**
	* Mobileid set the errors
	*
	* @return 	boolean	true on success, false on failure
	*/
	private function setError($msg, $error_type = 'error') {
		
		if (!strlen($msg)) {
			return false;
		}

		$this->response_error          = true;
		$this->response_error_type     = $error_type;
		$this->response_error_message  = $msg;
		
		return true;
	}

	/**
	* Mobileid clean up the temporaries files
	*
	* @return 	boolean	true on success, false on failure
	*/
	private function setRequestSuccess() {
		
		$this->response_error = false;
		$this->response_error_type = false;

		return true;		
	}
}
?>
