<?php
require("db.php");
require("auth.php");
if($conn) {
    include "./templates/index.html";
    if (!empty($_SESSION['user_id'])) {
        $username = htmlspecialchars($_SESSION['username']);
        echo '<div class="session-bar">';
        echo '<div class="session-info">Signed in as <span class="pill">' . $username . '</span></div>';
        echo '<div class="session-actions">';
        echo '<a href="/autologin.php" class="button">Auto-login</a>';
        echo '<a href="/logout.php" class="button">Logout</a>';
        echo '</div>';
        echo '</div>';
        if (!empty($_SESSION['autologin_link'])) {
            $link = htmlspecialchars($_SESSION['autologin_link']);
            echo '<div class="helper-text">Your auto-login link: <a href="' . $link . '">' . $link . '</a></div>';
            unset($_SESSION['autologin_link']);
        }
    } else {
        echo '<div class="session-bar">';
        echo '<div class="session-info">Sign in to use reporting, deletion, and admin tools.</div>';
        echo '<div class="session-actions">';
        echo '<a href="/login.php" class="button">Login</a>';
        echo '<a href="/register.php" class="button">Register</a>';
        echo '</div>';
        echo '</div>';
    }
    $stmt = $conn->prepare("SELECT * FROM document;");
    $stmt->execute();

    $result = $stmt->get_result();

    $results = [];
    while ($row = $result->fetch_assoc()) {
        $results[] = $row;
    }
    $count = 1;
    echo '<div class="gallery-container">';
    foreach ($results as $row) {
        echo '<div class="gallery-item item' . $count . '" style="--i: ' . $count . ';">';
        echo '<div class="image-blur"></div>';
        echo '<a href="view.php?title=' . $row['title'] . '" class="gallery-text">' . $row['title'] . '</a>';
        echo '</div>';
        $count += 1;
    }
    echo '</div>';

    echo '<style>';
    $count = 1;
    foreach ($results as $row) {
        echo ".item" . $count . " .image-blur { background-image: url('./uploads/" . $row['filename'] . "'); }";
        $count += 1;
    }
    echo '</style>';

    echo '</body>
          </html>';
    $stmt->close();

}
else {
    echo "Failed";
}

?>
