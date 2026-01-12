<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Radixia Frontend - Home</title>
    <style>
        body { font-family: sans-serif; padding: 2rem; max-width: 600px; margin: 0 auto; }
        input { display: block; width: 100%; margin: 10px 0; padding: 8px; }
        button { padding: 10px 20px; background: #2563eb; color: white; border: none; cursor: pointer; }
        .google-btn { background: #db4437; margin-top: 10px; width: 100%; }
        .divider { margin: 20px 0; border-top: 1px solid #ccc; }
        .status { margin-top: 1rem; padding: 1rem; background: #f3f4f6; display: none; }
    </style>
</head>
<body>
<h2>Register (Simulate Frontend)</h2>

<div id="registerForm">
    <input type="text" id="name" placeholder="Name" value="Test User">
    <input type="email" id="email" placeholder="Email (Check Mailpit after)" value="test@example.com">
    <input type="password" id="password" placeholder="Password" value="password">
    <input type="password" id="password_confirmation" placeholder="Confirm Password" value="password">

    <button onclick="register()">Register</button>
</div>

<div class="divider"></div>

<h3>Or Login with Social</h3>
<button class="google-btn" onclick="loginGoogle()">Login with Google</button>

<div id="output" class="status"></div>

<script>
    // --- GOOGLE LOGIN LOGIC ---
    function loginGoogle() {
        const clientId = 'YOUR_GOOGLE_CLIENT_ID_HERE';
        const redirectUri = 'http://localhost:3000/auth/google/callback';
        const scope = 'openid profile email';

        const url =
            `https://accounts.google.com/o/oauth2/v2/auth` +
            `?response_type=code` +
            `&client_id=${encodeURIComponent(clientId)}` +
            `&redirect_uri=${encodeURIComponent(redirectUri)}` +
            `&scope=${encodeURIComponent(scope)}`;

        window.location.href = url;
    }

    // --- EMAIL/PASSWORD REGISTER LOGIC ---
    async function register() {
        const output = document.getElementById('output');
        output.style.display = 'block';
        output.style.color = 'black';
        output.innerText = 'Sending request...';

        const data = {
            name: document.getElementById('name').value,
            email: document.getElementById('email').value,
            password: document.getElementById('password').value,
            password_confirmation: document.getElementById('password_confirmation').value,
            device_name: 'Test Frontend Browser'
        };

        try {
            const res = await fetch('http://127.0.0.1:8000/api/v1/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                body: JSON.stringify(data),
            });

            const json = await res.json();

            if (res.ok) {
                output.style.color = 'green';
                output.innerHTML =
                    `<strong>Success!</strong><br>` +
                    `Token: ${json.data.token.substring(0, 20)}...<br><br>` +
                    `Check your email (Mailpit) and click the verify link.`;
            } else {
                output.style.color = 'red';
                output.innerText = 'Error: ' + JSON.stringify(json);
            }
        } catch (e) {
            output.style.color = 'red';
            output.innerText = 'Network Error: ' + e.message;
        }
    }
</script>
</body>
</html>
<!-- php -S localhost:3000 router.php  -->