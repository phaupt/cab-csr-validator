<?php
/**
 * @version     1.0.0
 * @package     cab-csr-validator
 * @copyright   Copyright (C) 2012. All rights reserved.
 * @license     Licensed under the Apache License, Version 2.0 or later; see LICENSE.md
 * @author      Swisscom (Schweiz) AG
 */

define('__ROOT__', dirname(__FILE__)); 
require_once(__ROOT__.'/helpers/app.php');
require_once(__ROOT__.'/helpers/validator-helper.php');

/* New instance of the app class */
$app = new validator_app();

/* New instance of the validator class */
$validator = new validator_helper();

/* Do the request check */
if ($validator->checkRequest()) {
	$response_success = true;
}
?>
<!DOCTYPE html>
<html lang="<?php echo $app->language; ?>">
	<head>
		<meta charset="utf-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title><?php echo $app->getText('TITLE'); ?></title>
		<!-- Bootstrap -->
		<link href="assets/css/bootstrap.min.css" rel="stylesheet">
		<link href="assets/css/custom.css" rel="stylesheet">
	</head>
	<body>
		<div id="page-content-wrapper">
			<div class="container-fluid">
				<div class="row">
					<div class="col-md-10 col-md-offset-1">
						<div class="page-header">
							<h1><?php echo $app->getText('APP_TITLE'); ?></h1>
						</div>
						<?php if ($response_success) { ?>
						<table class="table table-bordered">
							<caption><?php echo $app->getText('APP_REQUEST_SUBJECT_SUBJECT'); ?></caption>
							<thead>
								<tr>
									<th><?php echo $app->getText('APP_REQUEST_SUBJECT_RDN'); ?></th>
									<th><?php echo $app->getText('APP_REQUEST_SUBJECT_VALUE'); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php if (strlen($validator->csr_cn)) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_CN'); ?></td>
									<td><?php echo $validator->csr_cn; ?></td>
								</tr>
								<?php } ?>
								<?php if (strlen($validator->csr_email)) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_EMAIL'); ?></td>
									<td><?php echo $validator->csr_email; ?></td>
								</tr>
								<?php } ?>
								<?php if (strlen($validator->csr_o)) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_O'); ?></td>
									<td><?php echo $validator->csr_o; ?></td>
								</tr>
								<?php } ?>
								<?php foreach($validator->csr_ou as $ou) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_OU'); ?></td>
									<td><?php echo $ou; ?></td>
								</tr>
								<?php } ?>
								<?php if (strlen($validator->csr_l)) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_L'); ?></td>
									<td><?php echo $validator->csr_l; ?></td>
								</tr>
								<?php } ?>
								<?php if (strlen($validator->csr_s)) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_S'); ?></td>
									<td><?php echo $validator->csr_s; ?></td>
								</tr>
								<?php } ?>
								<?php if (strlen($validator->csr_c)) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_C'); ?></td>
									<td><?php echo $validator->csr_c; ?></td>
								</tr>
								<?php } ?>
								<?php if ($validator->csr_keysize) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_KEY_SIZE'); ?></td>
									<td><?php echo $validator->csr_keysize.'-bits'; ?></td>
								</tr>
								<?php } ?>
								<?php if (count($validator->csr_sans)) { ?>
								<?php $i = 1; ?>
								<?php foreach($validator->csr_sans as $san) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SAN').' '.$i; ?></td>
									<td><?php echo $san; ?></td>
								</tr>
								<?php $i++; ?>						
								<?php } ?>
								<?php } ?>
								<?php if (count($validator->csr_domains)) { ?>
								<?php $i = 1; ?>
								<?php foreach($validator->csr_domains as $domain) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_DOMAIN').' '.$i; ?></td>
									<td><?php echo $domain; ?></td>
								</tr>
								<?php $i++; ?>						
								<?php } ?>
								<?php } ?>
							</tbody>
						</table>
						<?php } ?>
						<div>
						<?php foreach($validator->response_checks as $response_check) { ?>
							<p class="check <?php echo $response_check["result"] ? 'bg-success' : 'bg-danger'; ?>">
								<?php echo '<strong>'.$response_check["check"].'</strong>, '; ?>
								<em>
								<?php if (!$response_check["result"]) { ?>
								<?php echo $app->getText('APP_SUBMIT_CHECK_FAILED'); ?>
								<?php } else { ?>
								<?php echo $app->getText('APP_SUBMIT_CHECK_PASSED'); ?>
								<?php } ?>
								</em>
								<?php if (strlen($response_check["detail"])) { ?>
								<?php echo ', '.$response_check["detail"]; ?>
								<?php } ?>
							</p>
						<?php } ?>
						</div>
						<footer>Swisscom (Schweiz) AG <cite title="Source Title">CSR Validator</cite></footer>
					</div>
				</div>
			</div>
		</div>
		<div class="footer">
			<div class="col-md-6 col-md-offset-1 container">
				<p class="text-muted"><?php echo str_replace('%s', number_format($validator->duration, 3), $app->getText('APP_SUBMIT_SUCCESS_DURATION')); ?></p>
			</div>
		</div>
	</body>
</html>

