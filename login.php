<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( ) );
dvwaDatabaseConnect();

if( isset( $_POST[ 'Login' ] ) ) {
    // Anti-CSRF
    $session_token = $_SESSION['session_token'] ?? '';
    checkToken($_REQUEST['user_token'], $session_token, 'login.php');

    $user = stripslashes($_POST['username']);
    $user = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $user);

    $pass = stripslashes($_POST['password']);
    $pass = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $pass);
    $pass = md5($pass);

    $query = "SELECT table_schema, table_name, create_time
              FROM information_schema.tables
              WHERE table_schema='" . $_DVWA['db_database'] . "' AND table_name='users'
              LIMIT 1";

    $result = @mysqli_query($GLOBALS["___mysqli_ston"], $query);
    if (!$result || mysqli_num_rows($result) != 1) {
        dvwaMessagePush("First time using DVWA.<br />Need to run 'setup.php'.");
        dvwaRedirect(DVWA_WEB_PAGE_TO_ROOT . 'setup.php');
        exit;
    }

    $query = "SELECT * FROM `users` WHERE user='$user' AND password='$pass';";
    $result = @mysqli_query($GLOBALS["___mysqli_ston"], $query);

    if (!$result) {
        error_log('Login query failed: ' . mysqli_error($GLOBALS["___mysqli_ston"]));
        dvwaMessagePush('An internal error occurred. Please contact the administrator.');
        dvwaRedirect('login.php');
        exit;
    }

    if (mysqli_num_rows($result) === 1) {
        dvwaMessagePush("You have logged in as '{$user}'");
        dvwaLogin($user);
        dvwaRedirect(DVWA_WEB_PAGE_TO_ROOT . 'index.php');
        exit;
    }

    // Login failed
    dvwaMessagePush('Login failed');
    dvwaRedirect('login.php');
    exit;
}

// (resto del código sin cambios: HTML, CSRF token, etc.)
?>
