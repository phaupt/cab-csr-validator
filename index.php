<?php
/**
 * @version     1.0.0
 * @package     cab-csr-validator
 * @copyright   Copyright (C) 2012. All rights reserved.
 * @license     Licensed under the Apache License, Version 2.0 or later; see LICENSE.md
 * @author      Swisscom (Schweiz) AG
 */
    
define('__ROOT__', dirname(__FILE__));

header("Cache-Control: no-cache, no-store, must-revalidate"); // HTTP 1.1.
header("Pragma: no-cache"); // HTTP 1.0.
header("Expires: 0"); // Proxies.

require_once(__ROOT__.'/helpers/app.php');
$app = new validator_app();
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
		<!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
		<!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
		<!--[if lt IE 9]>
		<script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
		<script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
		<![endif]-->
	</head>
	<body>
		<div id="page-content-wrapper">
			<div class="container-fluid">
				<div class="row">
					<div class="col-md-10 col-md-offset-1">
						<div class="page-header">
							<h1><?php echo $app->getText('APP_TITLE'); ?></h1>
						</div>
						<p><?php echo $app->getText('APP_INTRO'); ?></p>
						<form class="form-horizontal" id="validator_form" action="request.php" method="post" enctype="multipart/form-data">
							<div class="form-group">
								<label class="col-md-1 control-label" for="csr_upload"><?php echo $app->getText('APP_CSR_UPLOAD_LABEL'); ?></label>
								<div class="col-md-5">
									<div class="input_file_button_zone">
										<a class="btn btn-primary" href="#">
											<?php echo $app->getText('APP_CSR_TEXT_UPLOAD_CHOOSE'); ?>
											<input type="file" style='position:absolute;z-index:2;top:0;left:0;filter: alpha(opacity=0);-ms-filter:"progid:DXImageTransform.Microsoft.Alpha(Opacity=0)";opacity:0;background-color:transparent;color:transparent;' name="csr_upload" id="csr_upload">
										</a>
										&nbsp;
										<span class='label label-info' id="upload-file-info"></span>
									</div>
									<p class="help-block"><?php echo $app->getText('APP_CSR_TEXT_UPLOAD_HELP'); ?></p>
								</div>
							</div>
							<div class="form-group">
								<label class="col-md-1 control-label" for="csr_text"><?php echo $app->getText('APP_CSR_TEXT_LABEL'); ?></label>
								<div class="col-md-5">
									<textarea class="form-control" rows="5" id="csr_text" name="csr_text" placeholder="<?php echo $app->getText('APP_CSR_TEXT_INPUT_PLACEOLDER'); ?>"></textarea>
								</div>
							</div>
							<div class="form-group">
								<div class="col-md-4">
									<label class="col-md-2 col-md-offset-1 control-label" for="s"></label>
									<div id="button_zone">
										<button class="btn btn-primary" id="submit_btn_remove"><?php echo $app->getText('APP_SUBMIT_BTN_REMOVE'); ?></button>
										<button class="btn btn-primary" id="submit_btn_send" type="submit"><?php echo $app->getText('APP_SUBMIT_BTN_SEND'); ?></button>
									</div>
									<div id="spinner"></div>
								</div>
							</div>
							<input type="hidden" value="<?php echo $app->language; ?>" name="lang" />
						</form>
					</div>
				</div>
			</div>
		</div>
		<!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
		<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
		<script src="assets/js/bootstrap.min.js"></script>
		<script src="assets/js/validator.js"></script>
	</body>
</html>
