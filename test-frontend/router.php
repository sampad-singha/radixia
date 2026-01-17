<?php
// router.php
$path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);

// If the file exists physically, serve it (e.g. /index.html, /email-verified.php, /callback.php)
if (file_exists(__DIR__ . $path) && !is_dir(__DIR__ . $path)) {
    return false; // let the built-in server serve it
}

// Routing
switch ($path) {
    case '/':
        require __DIR__ . '/index.php';
        break;

    case '/email-verified':
        require __DIR__ . '/email-verified.php';
        break;

    case '/auth/google/callback':
        require __DIR__ . '/callback.php';
        break;

    default:
        http_response_code(404);
        echo "404 Not Found: $path";
        break;
}
