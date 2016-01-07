<?php
/**
 * @version     1.0.0
 * @package     cab-csr-validator
 * @copyright   Copyright (C) 2012. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.md
 * @author      Swisscom (Schweiz AG)
 */
    
class validator_config {

	/* Configuration */
	
	/* Comodo API */
	// https://secure.comodo.net/api/pdf/latest/DecodeCSR.pdf
	public $api_url = "http://secure.comodo.net/products/!DecodeCSR";
	public $timeout = 120;
	public $showErrorCodes = "Y";
	public $showErrorMessages = "N";
	public $showFieldNames = "Y";
	public $showEmptyFields = "Y";
	public $showCN = "Y";
	public $showAddress = "Y";
	public $showPublicKey = "Y";
	public $showKeySize = "Y";
	public $showSANDNSNames = "Y";
	public $showCSR = "N";
	public $showCSRHashes = "N";
	public $showSignatureAlgorithm = "Y";
	public $countryNameType = "TWOCHAR";
	
	/* Request check default values */
	public $san_entries_max = 10;
}
?>
