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
						<?php if ($validator->csr_subject) { ?>
						<table class="table table-bordered">
							<h2><?php echo $app->getText('APP_REQUEST_SUBJECT_SUBJECT'); ?></h2>
							<thead>
								<tr>
									<th class="col-md-5"><?php echo $app->getText('APP_REQUEST_SUBJECT_RDN'); ?></th>
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
								<?php if (count($validator->csr_ou)) { ?>
								<?php foreach($validator->csr_ou as $ou) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_OU'); ?></td>
									<td><?php echo $ou; ?></td>
								</tr>
								<?php } ?>
								<?php } ?>
								<?php if (count($validator->csr_s)) { ?>
								<?php foreach($validator->csr_s as $s) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_S'); ?></td>
									<td><?php echo $s; ?></td>
								</tr>
								<?php } ?>
								<?php } ?>
								<?php if (strlen($validator->csr_l)) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_L'); ?></td>
									<td><?php echo $validator->csr_l; ?></td>
								</tr>
								<?php } ?>
								<?php if (count($validator->csr_st)) { ?>
								<?php foreach($validator->csr_st as $st) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_ST'); ?></td>
									<td><?php echo $st; ?></td>
								</tr>
								<?php } ?>
								<?php } ?>
								<?php if (strlen($validator->csr_c)) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_C'); ?></td>
									<td><?php echo $validator->csr_c; ?></td>
								</tr>
								<?php } ?>
								<?php if (count($validator->csr_others)) { ?>
								<?php foreach($validator->csr_others as $other) { ?>
								<tr>
									<td><?php echo $other['title']; ?></td>
									<td><?php echo $other['value']; ?></td>
								</tr>
								<?php } ?>
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
							</tbody>
						</table>
						<?php } ?>
						<?php if ($validator->csr_domains) { ?>
						<table class="table table-bordered">
							<h2><?php echo $app->getText('APP_REQUEST_DOMAINS'); ?></h2>
							<thead>
								<tr>
									<th class="col-md-5"><?php echo $app->getText('APP_REQUEST_SUBJECT_RDN'); ?></th>
									<th><?php echo $app->getText('APP_REQUEST_SUBJECT_VALUE'); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php $i = 1; ?>
								<?php foreach($validator->csr_domains as $domain) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_DOMAIN').' '.$i; ?></td>
									<td>
										<?php if (isset($domain["server"])) { ?>
										<a href="#" data-toggle="modal" data-target="#modal_domains_<?php echo $i; ?>"><?php echo $domain["domain"]; ?></a>
										<div class="modal fade" id="modal_domains_<?php echo $i; ?>" tabindex="-1" role="dialog" aria-labelledby="modal_domains_<?php echo $i; ?>_label">
											<div class="modal-dialog" role="document">
												<div class="modal-content">
													<div class="modal-header">
														<button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
														<h4 class="modal-title" id="myModalLabel"><?php echo $domain["domain"]; ?></h4>
													</div>
													<div class="modal-body">
														<?php echo $domain["whois"]; ?>
													</div>
													<div class="modal-footer">
														<button type="button" class="btn btn-default" data-dismiss="modal"><?php echo $app->getText('APP_REQUEST_DOMAIN_CLOSE'); ?></button>
													</div>
												</div>
											</div>
										</div>
										<a href="<?php echo 'http://'.$domain["server"]; ?>" target="_blank" title="<?php echo $app->getText('APP_REQUEST_DOMAIN_WHOIS'); ?>"><span class="glyphicon glyphicon-edit" aria-hidden="true"></span></a>
										<?php } else { ?>
										<?php echo $domain["domain"]; ?>
										<?php } ?>
									</td>
								</tr>
								<?php $i++; ?>
								<?php } ?>
							</tbody>
						</table>
						<?php } ?>
						<?php if ($validator->csr_ips) { ?>
						<table class="table table-bordered">
							<h2><?php echo $app->getText('APP_REQUEST_IPS'); ?></h2>
							<thead>
								<tr>
									<th class="col-md-5"><?php echo $app->getText('APP_REQUEST_SUBJECT_RDN'); ?></th>
									<th><?php echo $app->getText('APP_REQUEST_SUBJECT_VALUE'); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php $i = 1; ?>
								<?php foreach($validator->csr_ips as $ip) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_IP').' '.$i; ?></td>
									<td>
										<?php if (isset($ip["server"])) { ?>
										<a href="#" data-toggle="modal" data-target="#modal_ips_<?php echo $i; ?>"><?php echo $ip["domain"]; ?></a>
										<div class="modal fade" id="modal_ips_<?php echo $i; ?>" tabindex="-1" role="dialog" aria-labelledby="modal_ips_<?php echo $i; ?>_label">
											<div class="modal-dialog" role="document">
												<div class="modal-content">
													<div class="modal-header">
														<button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
														<h4 class="modal-title" id="myModalLabel"><?php echo $ip["domain"]; ?></h4>
													</div>
													<div class="modal-body">
														<?php echo $ip["whois"]; ?>
													</div>
													<div class="modal-footer">
														<button type="button" class="btn btn-default" data-dismiss="modal"><?php echo $app->getText('APP_REQUEST_DOMAIN_CLOSE'); ?></button>
													</div>
												</div>
											</div>
										</div>
										<a href="<?php echo 'http://'.$ip["server"]; ?>" target="_blank" title="<?php echo $app->getText('APP_REQUEST_DOMAIN_WHOIS'); ?>"><span class="glyphicon glyphicon-edit" aria-hidden="true"></span></a>
										<?php } else { ?>
										<?php echo $ip["domain"]; ?>
										<?php } ?>
									</td>
								</tr>
								<?php $i++; ?>
								<?php } ?>
							</tbody>
						</table>
						<?php } ?>
						<?php if ($validator->response_checks) { ?>
						<table class="table table-bordered">
							<h2><?php echo $app->getText('APP_REQUEST_CHECKS'); ?></h2>
							<thead>
								<tr>
									<th class="col-md-1"><?php echo $app->getText('APP_REQUEST_TEST_HEADER_1'); ?></th>
									<th class="col-md-4"><?php echo $app->getText('APP_REQUEST_TEST_HEADER_2'); ?></th>
									<th><?php echo $app->getText('APP_REQUEST_TEST_HEADER_3'); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php $i = 1; ?>
								<?php foreach($validator->response_checks as $response_check) { ?>
								<tr class="<?php echo $response_check["result"] ? 'success' : 'danger'; ?>">
									<td><?php echo $i; ?></td>
									<td><?php echo '<strong>'.$response_check["check"].'</strong>'; ?></td>
									<td>
										<?php if (isset($response_check["detail"])) { ?>
										<?php echo '<em>'.$response_check["result_msg"].'</em>, '.$response_check["detail"]; ?>
										<?php } else { ?>
										<?php echo '<em>'.$response_check["result_msg"].'</em>'; ?>
										<?php } ?>
									</td>
								</tr>
								<?php $i++; ?>
								<?php } ?>
							</tbody>
						</table>
						<?php } ?>
						<?php if ($validator->response_results) { ?>
						<table class="table table-bordered">
							<h2><?php echo $app->getText('APP_REQUEST_RESULTS'); ?></h2>
							<thead>
								<tr>
									<th class="col-md-1"><?php echo $app->getText('APP_REQUEST_TEST_HEADER_1'); ?></th>
									<th class="col-md-4"><?php echo $app->getText('APP_REQUEST_TEST_HEADER_2'); ?></th>
									<th><?php echo $app->getText('APP_REQUEST_TEST_HEADER_3'); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php $i = 1; ?>
								<?php foreach($validator->response_results as $response_result) { ?>
								<tr class="<?php echo $response_result["result"] ? 'success' : 'danger'; ?>">
									<td><?php echo $i; ?></td>
									<td><?php echo '<strong>'.$response_result["check"].'</strong>'; ?></td>
									<td>
										<?php if (isset($response_result["detail"])) { ?>
										<?php echo '<em>'.$response_result["result_msg"].'</em>, '.$response_result["detail"]; ?>
										<?php } else { ?>
										<?php echo '<em>'.$response_result["result_msg"].'</em>'; ?>
										<?php } ?>
									</td>
								</tr>
								<?php $i++; ?>
								<?php } ?>
							</tbody>
						</table>
						<?php } ?>
					</div>
				</div>
			</div>
		</div>
		<div class="container">     
			<div class="span12 centered-text">
				<div>
					<a href="#" data-toggle="modal" data-target="#modal_openssl"><?php echo $app->getText('APP_REQUEST_OPENSSL_DETAIL'); ?></a>
					<div class="modal fade" id="modal_openssl" tabindex="-1" role="dialog" aria-labelledby="modal_openssl_label">
						<div class="modal-dialog" role="document">
							<div class="modal-content">
								<div class="modal-header">
									<button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
									<h4 class="modal-title" id="myModalLabel"><?php echo $validator->file_path; ?></h4>
								</div>
								<div class="modal-body openssl">
									<?php echo $validator->openssl_output; ?>
								</div>
								<div class="modal-footer">
									<button type="button" class="btn btn-default" data-dismiss="modal"><?php echo $app->getText('APP_REQUEST_DOMAIN_CLOSE'); ?></button>
								</div>
							</div>
						</div>
					</div>
				</div>
				<div>
					<p class="text-muted"><?php echo str_replace('%s', number_format($validator->duration, 3), $app->getText('APP_SUBMIT_SUCCESS_DURATION')); ?></p>
				</div>
				<a class="btn btn-default active" href="index.php" role="button"><?php echo $app->getText('APP_REQUEST_BACK'); ?></a>
			</div>
		</div>
		<div class="footer">
			<div class="col-md-6 col-md-offset-1 container">
				&nbsp;
			</div>
		</div>
		<!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
		<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
		<script src="assets/js/bootstrap.min.js"></script>
		<script src="assets/js/validator.js"></script>
	</body>
</html>

