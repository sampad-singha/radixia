<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Email Verified</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0fdf4; }
        .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
        h1 { color: #166534; }
    </style>
</head>
<body>
<div class="card">
    <?php if (isset($_GET['verified']) && $_GET['verified'] == '1'): ?>
        <div style="font-size: 50px;">✅</div>
        <h1>Email Verified!</h1>
        <p>Your account is now active.</p>
        <p><a href="index.php">Go back to Login</a></p>
    <?php else: ?>
        <div style="font-size: 50px;">❓</div>
        <h1>Unknown Status</h1>
        <p>We couldn't confirm the verification.</p>
    <?php endif; ?>
</div>
</body>
</html>
