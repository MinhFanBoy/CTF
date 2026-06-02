<?php
require("db.php");
require("auth.php");
require_login();
    include "./templates/view.html";
    if ($_SERVER['REQUEST_METHOD'] == 'GET') {
        try {
    $title = $_GET['title'] ?? '';
    if (!preg_match('/^[a-zA-Z0-9\\\'"-*]+$/', $title)) {
        echo "Invalid title.";
        exit;       
    }
	$title = addslashes($title);
	$title = strtolower($title); 
    $forbidden_strings = ['top secret document', '%', '_','#', '&', ';', '--', '/*', '*/'];
	$contains_forbidden_string = false;
	foreach ($forbidden_strings as $str) {
    		if (strpos($title, $str) !== false) {
	        	$contains_forbidden_string = true;
        		break;
    		}
	}
            if (!$contains_forbidden_string) {
                $sql = "SELECT * FROM document WHERE title LIKE '$title'";
                $result = $conn->query($sql);
                if ($row = $result->fetch_assoc()) {
                    echo '<h1 class="title">' . htmlspecialchars($row['title']) . '</h1>';
                    echo '<img src="/uploads/' . htmlspecialchars($row['filename']) . '" alt="Document Image" class="document-image" width="500" height="500">';
                    echo '<p class="content">' . htmlspecialchars($row['content']) . '</p>';
                    echo '</div>
                  </body>
                  </html>';
                } else {
                    echo "No records found.";
                }
            } else {
                echo "The title contains forbidden words.";
            }
        } catch (mysqli_sql_exception $e) {
            echo "Query failed";
        }
    }
    else {
        echo "<script>alert('This is an unusual approach.');</script>";
        echo "<script>location.href='/TestBuild/index.php'</script>";
    }
?>
