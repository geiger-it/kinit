<?php
error_reporting(E_ALL | E_NOTICE);
require_once(dirname(__FILE__) . '/Auth.php');
?>
<form action="" method="post">
<input type="text" name="username" /><br />
<input type="password" name="password" /><br />
<input type="submit" /><br />
</form>
Result: 
<?php
if (!$_POST) return;

$result = $auth->login($_POST['username'], $_POST['password']);

if ($result) echo 'Success';
else echo 'Failure';
?>