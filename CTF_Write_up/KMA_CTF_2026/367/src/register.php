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
    $confirm = $_POST['confirm_password'] ?? '';

    if ($username === '' || $password === '' || $confirm === '') {
        $error = 'All fields are required.';
    } else if (!preg_match('/^[a-zA-Z0-9_]{3,32}$/', $username)) {
        $error = 'Username must be 3-32 characters (letters, numbers, underscore).';
    } else if (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters.';
    } else if ($password !== $confirm) {
        $error = 'Passwords do not match.';
    } else {
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $exists = $result->fetch_assoc();
        $stmt->close();

        if ($exists) {
            $error = 'Username is already taken.';
        } else {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
            $stmt->bind_param('ss', $username, $hash);
            if ($stmt->execute()) {
                session_regenerate_id(true);
                $_SESSION['user_id'] = $stmt->insert_id;
                $_SESSION['username'] = $username;
                $code = bin2hex(random_bytes(16));
                $record = [
                    'status' => 'active',
                    'email_list' => '',
                    'token' => $code,
                    'expiry_mode' => 'unchecked',
                    'expires_on' => date('Y-m-d', strtotime('+30 days')),
                    'unlimited_use' => 'checked',
                ];
                $serialized = serialize($record);
                $meta_stmt = $conn->prepare("INSERT INTO user_meta (user_id, meta_key, meta_value) VALUES (?, 'vault_autologin_record', ?) ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)");
                $meta_stmt->bind_param('is', $_SESSION['user_id'], $serialized);
                $meta_stmt->execute();
                $meta_stmt->close();
                $_SESSION['autologin_link'] = '/autologin.php?vault_key=' . urlencode($code);
                header('Location: /index.php');
                exit;
            }
            $stmt->close();
            $error = 'Registration failed. Try again.';
        }
    }
}

include "./templates/register.html";
?>
