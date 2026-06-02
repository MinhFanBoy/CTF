<?php
require("db.php");
require("auth.php");
require_login();

function archive_base64url_encode($value) {
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function archive_base64url_decode($value) {
    $padding = strlen($value) % 4;
    if ($padding !== 0) {
        $value .= str_repeat('=', 4 - $padding);
    }

    return base64_decode(strtr($value, '-_', '+/'), true);
}

function archive_ticket_key() {
    if (empty($_SESSION['archive_ticket_key'])) {
        $_SESSION['archive_ticket_key'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['archive_ticket_key'];
}

function archive_issue_ticket($preview) {
    $state = serialize([
        'scope' => 'legacy_snapshot',
        'preview' => $preview,
        'issued_at' => time(),
    ]);
    $sealed_state = archive_base64url_encode($state);
    $packet = [
        'state' => $sealed_state,
        'mac' => hash_hmac('sha256', $sealed_state, archive_ticket_key()),
    ];

    return archive_base64url_encode(json_encode($packet));
}

function archive_open_ticket($ticket) {
    $packet_raw = archive_base64url_decode($ticket);
    $packet = $packet_raw === false ? null : json_decode($packet_raw, true);
    if (!is_array($packet) || !is_string($packet['state'] ?? null) || !is_string($packet['mac'] ?? null)) {
        return null;
    }

    $expected_mac = hash_hmac('sha256', $packet['state'], archive_ticket_key());
    if (!hash_equals($expected_mac, $packet['mac'])) {
        return null;
    }

    $state_raw = archive_base64url_decode($packet['state']);
    $state = $state_raw === false ? null : @unserialize($state_raw, ['allowed_classes' => false]);
    if (!is_array($state) || ($state['scope'] ?? '') !== 'legacy_snapshot') {
        return null;
    }

    $issued_at = (int)($state['issued_at'] ?? 0);
    if ($issued_at < time() - 300 || $issued_at > time() + 10) {
        return null;
    }

    return is_string($state['preview'] ?? null) ? $state['preview'] : null;
}

$preview_files = [
    'retention' => 'retention.php',
    'handover' => 'handover.php',
];
$preview_name = 'retention';
$notice = '';

if (isset($_GET['ticket'])) {
    $opened_preview = archive_open_ticket($_GET['ticket']);
    if (isset($preview_files[$opened_preview])) {
        $preview_name = $opened_preview;
    } else {
        $notice = 'Snapshot ticket rejected.';
    }
}

$ticket = archive_issue_ticket($preview_name);
$preview_root = realpath(__DIR__ . '/templates/archive_previews');
$preview_path = realpath($preview_root . DIRECTORY_SEPARATOR . $preview_files[$preview_name]);
$preview_html = '';

if ($preview_root !== false &&
    $preview_path !== false &&
    strpos($preview_path, $preview_root . DIRECTORY_SEPARATOR) === 0) {
    ob_start();
    include($preview_path);
    $preview_html = ob_get_clean();
}

include "./templates/archive.html";
?>
