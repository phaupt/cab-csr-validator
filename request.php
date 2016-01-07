<?php
/**
 * @version     1.0.0
 * @package     mobileid-helper
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
$validator->checkRequest();

//var_dump($validator->x509_content);
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
	</head>
	<body>
		<div id="page-content-wrapper">
			<div class="container-fluid">
				<div class="row">
					<div class="col-md-10 col-md-offset-1">
						<div class="page-header">
							<h1><?php echo $app->getText('APP_TITLE'); ?></h1>
						</div>
						<blockquote>
							<?php if ($validator->response_error) { ?>
							<p class="text-danger"><?php echo $validator->response_error_message; ?></p>
							<?php } else { ?>
							<p class="text-success"><?php echo $app->getText('APP_SUBMIT_SUCCESS'); ?></p>
							<?php } ?>
							<footer>Swisscom (Schweiz) AG <cite title="Source Title">CSR Validator</cite></footer>
						</blockquote>
						<table class="table table-bordered">
							<caption><?php echo $app->getText('APP_REQUEST_SUBJECT_SUBJECT'); ?></caption>
							<thead>
								<tr>
									<th><?php echo $app->getText('APP_REQUEST_SUBJECT_RDN'); ?></th>
									<th><?php echo $app->getText('APP_REQUEST_SUBJECT_VALUE'); ?></th>
								</tr>
							</thead>
							<tbody>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_CN'); ?></td>
									<td><?php echo $validator->csr_cn; ?></td>
								</tr>
								<?php if ($validator->response_error) { ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_EMAIL'); ?></td>
									<td><?php echo $validator->csr_email; ?></td>
								</tr>
								<?php } ?>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_OU'); ?></td>
									<td><?php echo $validator->csr_ou; ?></td>
								</tr>

								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_O'); ?></td>
									<td><?php echo $validator->csr_o; ?></td>
								</tr>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_L'); ?></td>
									<td><?php echo $validator->csr_l; ?></td>
								</tr>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_S'); ?></td>
									<td><?php echo $validator->csr_s; ?></td>
								</tr>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SUBJECT_C'); ?></td>
									<td><?php echo $validator->csr_c; ?></td>
								</tr>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_KEY_SIZE'); ?></td>
									<td><?php echo $validator->csr_keysize; ?> bits</td>
								</tr>
								<tr>
									<td><?php echo $app->getText('APP_REQUEST_SAN'); ?></td>
									<td><?php echo $validator->csr_san; ?></td>
								</tr>
							</tbody>
						</table>
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

