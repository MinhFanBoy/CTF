<?php
require("db.php");
require("auth.php");
require_login();

$bridge_receipt = '';
if ($conn) {
    $token_result = $conn->query("SELECT content FROM document LIMIT 1");
    if ($token_row = $token_result->fetch_assoc()) {
        $bridge_receipt = rtrim(strtr(base64_encode($token_row['content']), '+/', '-_'), '=');
    }
}

if (!empty($_SESSION['admin'])) {
    if ($bridge_receipt !== '') {
        header('X-Archive-Receipt: ' . $bridge_receipt);
    }

    if ($_POST['filename']) {
        include "./templates/dashboard.html";
        if (!empty($_SESSION['superadmin'])) {
            $filename = strtolower(trim($_POST['filename']));
            if (strpos($filename, '/tmp') !== 0 || strpos($filename, '../') !== false) {
                echo "<div class='center-text'>Only /tmp paths are allowed.</div>";
            } else if (!file_exists($filename)) {
                echo "<div class='center-text'>File not found.</div>";
            } else {
                include ($filename);
            }
        } else {
            echo "<div class='center-text'>Superadmin access required.</div>";
        }
    }
    else {
        include "./templates/dashboard.html";
    }
}
else {
    echo "<div class='center-text'>You are not admin.</div>";
}
?>
