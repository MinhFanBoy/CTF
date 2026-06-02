<?php
require("db.php");
require("auth.php");
require_login();

function generate_random_name($minLen = 10, $maxLen = 20) {
    $length = random_int($minLen, $maxLen);
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    $upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $name = '';

    for ($i = 0; $i < $length; $i++) {
        $name .= $chars[random_int(0, strlen($chars) - 1)];
    }

    $pos = random_int(0, $length - 1);
    $name[$pos] = $upper[random_int(0, strlen($upper) - 1)];

    return $name;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' and $_POST['title'] and $_POST['content']) {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        if (isset($_FILES['file']) && $_FILES['file']['error'] == 0) {
            $maxBytes = 2 * 1024 * 1024;
            if ($_FILES['file']['size'] > $maxBytes) {
                echo "<script>alert('File size must be under 2MB.');</script>";
                echo "<script>location.href='/index.php'</script>";
                exit;
            }
            $allowedTypes = ['image/png' => 'png', 'image/jpeg' => 'jpg'];
            $fileType = $_FILES['file']['type'];

            if (array_key_exists($fileType, $allowedTypes)) {
                $fileData = file_get_contents($_FILES['file']['tmp_name']);
                if ($fileData === false) {
                    echo "<script>alert('Upload failed.');</script>";
                    echo "<script>location.href='/index.php'</script>";
                    exit;
                }

                $forbiddenTerms = ['var', 'html', 'assets', 'uploads', 'templates','flag'];
                $blockedTerm = '';
                foreach ($forbiddenTerms as $term) {
                    if (stripos($fileData, $term) !== false) {
                        $blockedTerm = $term;
                        break;
                    }
                }

                if ($blockedTerm !== '') {
                    echo "<script>alert('Upload blocked.');</script>";
                    echo "<script>location.href='/index.php'</script>";
                    exit;
                }

                $uploadPath = './uploads/';
                do {
                    $randomFileName = generate_random_name() . '.' . $allowedTypes[$fileType];
                } while (file_exists($uploadPath . $randomFileName));

                if (!is_dir($uploadPath)) {
                    mkdir($uploadPath, 0777, true);
                }

                if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadPath . $randomFileName)) {
                    $tempCopyPath = '';
                    if (!empty($_POST['temp_copy']) && !empty($_SESSION['admin'])) {
                        $tmpRoot = sys_get_temp_dir();
                        $tmpFolder = $tmpRoot . DIRECTORY_SEPARATOR . bin2hex(random_bytes(8));
                        if (!is_dir($tmpFolder)) {
                            mkdir($tmpFolder, 0700, true);
                        }
                        $tempCopyPath = $tmpFolder . DIRECTORY_SEPARATOR . $randomFileName;
                        if (!copy($uploadPath . $randomFileName, $tempCopyPath)) {
                            $tempCopyPath = '';
                        }
                    }
                    try {
                        $title = addslashes($_POST['title']);
                        $content = $_POST['content'];
                        $stmt = $conn->prepare("INSERT INTO document (title, content,filename) VALUES (?, ?, ?)");
                        $stmt->bind_param('sss', $title, $content, $randomFileName);

                        $stmt->execute();
                    } catch (mysqli_sql_exception $e) {
                        echo "Query failed";
                    }
                    echo "<script>alert('$randomFileName')</script>";
                    if (!empty($tempCopyPath)) {
                        $safePath = addslashes($tempCopyPath);
                        echo "<script>alert('Temp copy created: $safePath')</script>";
                    }
                    echo "<script>alert('The file has been uploaded successfully.');</script>";
                    echo "<script>location.href='/index.php'</script>";
                } else {
                    echo "<script>alert('Error. Please Contact admin.');</script>";
                    echo "<script>location.href='/index.php'</script>";
                }
            }
            else {
                echo "<script>alert('Only PNG and JPG files are allowed.');</script>";
                echo "<script>location.href='/index.php'</script>";
            }
        }
        else {
            echo "<script>alert('Please upload an image as well. Only png and jpg are allowed.');</script>";
            echo "<script>location.href='/index.php'</script>";
        }
    }

} else if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    include "./templates/report.html";
} else {
    echo "BLOCKED";
}
?>

