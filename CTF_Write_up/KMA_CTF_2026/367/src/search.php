<?php
require("db.php");
require("auth.php");
require_login();

function search_legacy_text($value) {
    $value = str_replace(["\0", "\r", "\n"], '', (string)$value);
    return substr(trim($value), 0, 80);
}

$query = search_legacy_text($_GET['q'] ?? '');
$mode = $_GET['mode'] ?? 'title';
$sort = $_GET['sort'] ?? 'recent';
$direction = strtolower($_GET['dir'] ?? 'asc') === 'desc' ? 'DESC' : 'ASC';

$legacy_filters = [
    'title' => "title LIKE CONCAT('%', ?, '%')",
    'filename' => "filename LIKE CONCAT('%', ?, '%')",
];
$legacy_sort = [
    'recent' => 'filename',
    'title' => 'title',
];

if (!isset($legacy_filters[$mode])) {
    $mode = 'title';
}
if (!isset($legacy_sort[$sort])) {
    $sort = 'recent';
}

$documents = [];
$notice = '';

if (isset($_GET['q'])) {
    $sql = "SELECT title, filename
            FROM document
            WHERE title <> ? AND " . $legacy_filters[$mode] . "
            ORDER BY " . $legacy_sort[$sort] . " " . $direction . "
            LIMIT 12";
    $hidden_title = 'TOP SECRET DOCUMENT';
    $stmt = $conn->prepare($sql);

    if ($stmt) {
        $stmt->bind_param('ss', $hidden_title, $query);
        $stmt->execute();
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            $documents[] = $row;
        }
        $stmt->close();
    }

    if (empty($documents)) {
        $notice = 'No public snapshots matched the legacy filter.';
    }
}

include "./templates/search.html";
?>
