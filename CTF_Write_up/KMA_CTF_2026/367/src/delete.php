<?php
require("db.php");
require("auth.php");
require_login();
ini_set('phar.readonly',0);
class PreviewState {
    public $endpoint;
    private $headers;
    private $payload;
    private $sessionNote;

    function __construct($endpoint, $payload = '', $sessionNote = '', $headers = array()) {
        $this->endpoint = $endpoint;
        $this->payload = $payload;
        $this->sessionNote = $sessionNote;
        $this->headers = $headers;
    }

    function __wakeup() {
        if (empty($_SESSION['admin'])) {
            $this->sessionNote = 'discarded';
            $this->headers = [CURLOPT_USERAGENT => 'discarded'];
            return;
        }
        if (empty($_SESSION['superadmin'])) {
            $this->headers = [CURLOPT_USERAGENT => 'discarded'];
        }
    }

    function flush() {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        if (!empty($this->payload)) {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $this->payload);
        }

        if (!empty($this->sessionNote)) {
            curl_setopt($ch, CURLOPT_COOKIE, $this->sessionNote);
        }

        if (!empty($this->headers)) {
            $option = array_key_first($this->headers);
            $value = $this->headers[$option];
            curl_setopt($ch, $option, $value);
        }

        $output = curl_exec($ch);
        echo $output;
        curl_close($ch);
    }
}

class PendingPreview {
    public $state;

    function __construct($state) {
        $this->state = $state;
    }

    function __destruct() {
        if ($this->state instanceof PreviewState) {
            $this->state->flush();
        }
    }
}
    if ($_SERVER['REQUEST_METHOD'] == 'GET') {
        include "./templates/delete.html";

    }
    else {
        if($_POST['title']) {
            $title = $_POST['title'];
            if (strpos($title, '..') !== false) {
                echo "Filtered.";
                exit(-1);
            }

            $filePath = $title;
            $imageType = pathinfo($filePath, PATHINFO_EXTENSION);
	    $allowedTypes = ['png', 'jpg', 'jpeg'];
	    if (!in_array(strtolower($imageType), $allowedTypes)) {
    		echo "Invalid image type.";
    		exit(-1);
	    }
	    $imageData = file_get_contents($filePath);
	    if ($imageData == null) {
		$filePath = './uploads/' . $filePath;
		$imageData = file_get_contents($filePath);
	    }
            $base64 = 'data:image/' . $imageType . ';base64,' . base64_encode($imageData);
            include "./templates/delete_real.html";
            echo '<img src="' . $base64 . '" alt="Deleted Image File">';
            try {
                $stmt = $conn->prepare("DELETE FROM document where filename=?");
                $stmt->bind_param('s', $title);
                $stmt->execute();
                $valid_filename_pattern = '/^[a-zA-Z0-9_.-]+$/';

                if (preg_match($valid_filename_pattern, $title)) {
                    system("rm -rf ./uploads/" . escapeshellarg($title));
                } else {
                    echo "Invalid file name.";
                    echo '</div>
                  </body>
                  </html>';
                    exit(-1);
                }
                echo "Success Deleted!";
                echo '</div>
                  </body>
                  </html>';
            } catch (mysqli_sql_exception $e) {
                echo "Query failed";
            }

        }
        else {
            echo "<script>alert('Error. Please Contact admin.');</script>";
            echo "<script>location.href='/index.php'</script>";
        }
    }
?>
