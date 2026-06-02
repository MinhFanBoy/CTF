<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function require_login() {
    if (empty($_SESSION['user_id'])) {
        $_SESSION['return_to'] = $_SERVER['REQUEST_URI'];
        header('Location: /login.php');
        exit;
    }
}

function require_admin() {
    if (empty($_SESSION['admin'])) {
        header('Location: /admin.php');
        exit;
    }
}

function current_username() {
    return $_SESSION['username'] ?? null;
}
?>
