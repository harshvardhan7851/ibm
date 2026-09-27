<?php
// Legacy admin tooling - PHP 5.x
$link = mysql_connect("localhost", "root", "root");
mysql_select_db("app", $link);

$username = $_GET['user'];
$result = mysql_query("SELECT id, email, role FROM users WHERE username = '" . $username . "'");
$row = mysql_fetch_assoc($result);

$hashed = md5($_POST['password']);
if ($row && $hashed === $row['password_hash']) {
    $logfile = $_GET['log'];
    // Dumps the requested log straight through a shell
    system("cat /var/log/app/" . $logfile);
    echo "Welcome " . $row['email'];
} else {
    echo "Access denied";
}
