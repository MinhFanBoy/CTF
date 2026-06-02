<?php
require("db.php");
require("auth.php");


function mock_sanitize_input($input) {
    $clean = stripslashes($input);
    $clean = strip_tags(trim($clean));
    $clean = preg_replace('/[^a-zA-Z0-9]+/', '', $clean);
    return $clean;
}
function mock_wp_json_encode($data) {
    return json_encode($data);
}
function mock_esc_like($text) {
    return addcslashes($text, '_%\\');
}

if (isset($_GET['vault_key'])) {
    $vault_key = mock_sanitize_input($_GET['vault_key']);
    $needle = '%' . mock_esc_like(mock_wp_json_encode($vault_key)) . '%';
    $stmt = $conn->prepare("SELECT user_id FROM user_meta WHERE meta_key = 'vault_autologin_record' AND meta_value LIKE ? ESCAPE '\\\\'");
    $stmt->bind_param('s', $needle);
    $stmt->execute();
    $result = $stmt->get_result();
    $user_ids = [];
    while ($row = $result->fetch_assoc()) {
        $user_ids[] = (int)$row['user_id'];
    }
    $stmt->close();

    if (count($user_ids) === 1) {
        $current_user_id = $user_ids[0];
        $meta_stmt = $conn->prepare("SELECT meta_value FROM user_meta WHERE user_id = ? AND meta_key = 'vault_autologin_record' LIMIT 1");
        $meta_stmt->bind_param('i', $current_user_id);
        $meta_stmt->execute();
        $meta_result = $meta_stmt->get_result();
        $meta_row = $meta_result->fetch_assoc();
        $meta_stmt->close();

        $record = $meta_row ? @unserialize($meta_row['meta_value']) : null;
        $status = is_array($record) ? ($record['status'] ?? '') : '';
        $expiry_mode = is_array($record) ? ($record['expiry_mode'] ?? '') : '';
        $expires_on = is_array($record) ? ($record['expires_on'] ?? '') : '';

        $valid = ($status === 'active');
        if ($expiry_mode !== 'unchecked' && $expires_on !== '') {
            $valid = $valid && ($expires_on >= date('Y-m-d'));
        }

        if ($valid) {
            $user_stmt = $conn->prepare("SELECT id, username FROM users WHERE id = ? LIMIT 1");
            $user_stmt->bind_param('i', $current_user_id);
            $user_stmt->execute();
            $user_result = $user_stmt->get_result();
            $user = $user_result->fetch_assoc();
            $user_stmt->close();

            if ($user) {
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['admin'] = ($user['username'] === 'admin');
                unset($_SESSION['superadmin']);
                header('Location: /index.php');
                exit;
            }
        }
    }

    $error = 'Auto-login failed.';
    include "./templates/login.html";
    exit;
}

require_login();

$is_admin = !empty($_SESSION['admin']);

$notice = '';
$generated_link = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'create_by_username') {
        $username = trim($_POST['username'] ?? '');
        $expires_on = $_POST['expires_on'] ?? date('Y-m-d', strtotime('+30 days'));
        $unlimited_use = !empty($_POST['unlimited_use']) ? 'checked' : '';

        if ($username === '') {
            $notice = 'Username is required.';
        } else {
            $user_stmt = $conn->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
            $user_stmt->bind_param('s', $username);
            $user_stmt->execute();
            $user_result = $user_stmt->get_result();
            $user = $user_result->fetch_assoc();
            $user_stmt->close();

            if ($user) {
                $code = bin2hex(random_bytes(16));
                $record = [
                    'status' => 'active',
                    'email_list' => '',
                    'token' => $code,
                    'expiry_mode' => 'unchecked',
                    'expires_on' => $expires_on,
                    'unlimited_use' => $unlimited_use ? 'checked' : '',
                ];
                $serialized = serialize($record);
                $stmt = $conn->prepare("INSERT INTO user_meta (user_id, meta_key, meta_value) VALUES (?, 'vault_autologin_record', ?) ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)");
                $stmt->bind_param('is', $user['id'], $serialized);
                if ($stmt->execute()) {
                    if ($user['id'] === (int)$_SESSION['user_id']) {
                        $generated_link = '/autologin.php?vault_key=' . urlencode($code);
                        $notice = 'Auto-login link generated for your username.';
                    } else {
                        $cleanup = $conn->prepare("DELETE FROM user_meta WHERE user_id = ? AND meta_key = 'vault_autologin_record'");
                        $cleanup->bind_param('i', $user['id']);
                        $cleanup->execute();
                        $cleanup->close();
                        $generated_link = '';
                        $notice = 'Username does not match your account.';
                    }
                } else {
                    $notice = 'Failed to create auto-login link.';
                }
                $stmt->close();
            } else {
                $notice = 'User not found.';
            }
        }
    }

    if ($action === 'revoke_by_username') {
        $username = trim($_POST['username'] ?? '');
        if ($username === '') {
            $notice = 'Username is required.';
        } else if (!$is_admin && $username !== ($_SESSION['username'] ?? '')) {
            $notice = 'You can only revoke your own auto-login link.';
        } else {
            $user_stmt = $conn->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
            $user_stmt->bind_param('s', $username);
            $user_stmt->execute();
            $user_result = $user_stmt->get_result();
            $user = $user_result->fetch_assoc();
            $user_stmt->close();

            if ($user) {
                $stmt = $conn->prepare("DELETE FROM user_meta WHERE user_id = ? AND meta_key = 'vault_autologin_record'");
                $stmt->bind_param('i', $user['id']);
                if ($stmt->execute()) {
                    $notice = 'Auto-login revoked for username.';
                } else {
                    $notice = 'Failed to revoke auto-login.';
                }
                $stmt->close();
            } else {
                $notice = 'User not found.';
            }
        }
    }

    if ($action === 'create' && $is_admin) {
        $user_id = (int)($_POST['user_id'] ?? 0);
        $expires_on = $_POST['expires_on'] ?? date('Y-m-d', strtotime('+30 days'));
        $unlimited_use = !empty($_POST['unlimited_use']) ? 'checked' : '';
        $code = bin2hex(random_bytes(16));

        $record = [
            'status' => 'active',
            'email_list' => '',
            'token' => $code,
            'expiry_mode' => 'unchecked',
            'expires_on' => $expires_on,
            'unlimited_use' => $unlimited_use ? 'checked' : '',
        ];

        $serialized = serialize($record);
        $stmt = $conn->prepare("INSERT INTO user_meta (user_id, meta_key, meta_value) VALUES (?, 'vault_autologin_record', ?) ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)");
        $stmt->bind_param('is', $user_id, $serialized);
        if ($stmt->execute()) {
            if ($user_id === (int)$_SESSION['user_id']) {
                $generated_link = '/autologin.php?vault_key=' . urlencode($code);
            } else {
                $generated_link = '';
            }
            $notice = 'Auto-login link generated.';
        } else {
            $notice = 'Failed to create auto-login link.';
        }
        $stmt->close();
    }

    if ($action === 'revoke' && $is_admin) {
        $user_id = (int)($_POST['user_id'] ?? 0);
        $stmt = $conn->prepare("DELETE FROM user_meta WHERE user_id = ? AND meta_key = 'vault_autologin_record'");
        $stmt->bind_param('i', $user_id);
        if ($stmt->execute()) {
            $notice = 'Auto-login revoked.';
        } else {
            $notice = 'Failed to revoke auto-login.';
        }
        $stmt->close();
    }
}

$users = [];
$users_by_id = [];
if ($is_admin) {
    $users_result = $conn->query("SELECT id, username FROM users ORDER BY username");
    while ($row = $users_result->fetch_assoc()) {
        $users[] = $row;
        $users_by_id[(int)$row['id']] = $row['username'];
    }
}

$records = [];
if ($is_admin) {
    $records_result = $conn->query("SELECT user_id, meta_value FROM user_meta WHERE meta_key = 'vault_autologin_record' ORDER BY user_id");
    while ($row = $records_result->fetch_assoc()) {
        $record = @unserialize($row['meta_value']);
        $records[] = [
            'user_id' => (int)$row['user_id'],
            'record' => is_array($record) ? $record : [],
        ];
    }
}

include "./templates/autologin.html";
?>
