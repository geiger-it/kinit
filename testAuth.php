<?php
error_reporting(-1);
ini_set('display_errors', '1');

require_once('KInit.php');
?>

<form action='' method=post>
	<input type=text name=username placeholder=Username /><br />
	<input type=password name=password placeholder=Password /><br />
	<input type=submit /><br />
</form>
<?php if (!$_POST) exit(); ?>

Result: <?php echo KInit::auth(@$_POST['username'], @$_POST['password']) ? 'Success' : 'False'; ?>
