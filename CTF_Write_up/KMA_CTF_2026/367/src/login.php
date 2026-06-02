<?php
require("db.php");
require("auth.php");

if (!empty($_SESSION['user_id'])) {
    header('Location: /index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $password === '') {
        $error = 'Missing username or password.';
    } else {
        $stmt = $conn->prepare("SELECT id, password_hash FROM users WHERE username = ?");
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        if ($user && password_verify($password, $user['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $username;
            $_SESSION['admin'] = ($username === 'admin');
            unset($_SESSION['superadmin']);
            $return_to = $_SESSION['return_to'] ?? '/index.php';
            unset($_SESSION['return_to']);
            header('Location: ' . $return_to);
            exit;
        }

        $error = 'Invalid username or password.';
    }
}

include "./templates/login.html";
?>
