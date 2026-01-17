<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Processing Login...</title>
    <style>body { font-family: sans-serif; text-align: center; padding-top: 50px; }</style>
</head>
<body>
<h2>Authenticating...</h2>
<div id="status">Please wait while we log you in.</div>

<script>
    async function handleCallback() {
        const status = document.getElementById('status');

        // 1. Get the 'code' from URL query params
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');

        if (!code) {
            status.innerText = "Error: No code returned from Google.";
            status.style.color = 'red';
            return;
        }

        // 2. Send code to your Backend API
        try {
            const response = await fetch('http://127.0.0.1:8000/api/v1/auth/social/google/callback_', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                    // Browser adds 'Origin: http://localhost:3000' automatically
                },
                body: JSON.stringify({
                    code: code,
                    device_name: 'Test Frontend'
                })
            });

            const data = await response.json();

            if (response.ok) {
                status.innerHTML = `
                        <h3 style="color:green">Login Successful!</h3>
                        <p><strong>User:</strong> ${data.data.user.name}</p>
                        <p><strong>Token:</strong> ${data.data.token.substring(0, 20)}...</p>
                        <p><a href="/index.php">Go Home</a></p>
                    `;
                // In real app: localStorage.setItem('token', data.data.token); window.location = '/dashboard';
            } else {
                status.innerText = "Login Failed: " + (data.message || JSON.stringify(data));
                status.style.color = 'red';
            }
        } catch (err) {
            status.innerText = "Network Error: " + err.message;
            status.style.color = 'red';
        }
    }

    handleCallback();
</script>
</body>
</html>
