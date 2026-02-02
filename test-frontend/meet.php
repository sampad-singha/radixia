<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LMS Dashboard - Classroom</title>
    <style>
        /* 1. LMS Layout CSS */
        body {
            font-family: sans-serif;
            margin: 0;
            display: flex;
            height: 100vh;
            background: #f0f2f5;
            overflow: hidden;
        }

        /* Sidebar */
        .sidebar {
            width: 260px;
            background: #1e293b;
            color: white;
            display: flex;
            flex-direction: column;
            padding: 20px;
        }

        .sidebar h3 {
            font-size: 1.2rem;
            margin-bottom: 2rem;
            color: #38bdf8;
        }

        .sidebar-nav {
            flex: 1;
        }

        .nav-item {
            padding: 12px;
            margin-bottom: 8px;
            border-radius: 6px;
            cursor: pointer;
            background: rgba(255, 255, 255, 0.05);
        }

        .nav-item:hover {
            background: rgba(255, 255, 255, 0.1);
        }

        /* Main Content Area */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            position: relative;
        }

        /* Tabs/Header */
        .header-tabs {
            height: 60px;
            background: white;
            border-bottom: 1px solid #e5e7eb;
            display: flex;
            align-items: center;
            padding: 0 20px;
            gap: 20px;
        }

        .tab {
            font-weight: 500;
            color: #64748b;
            cursor: pointer;
            padding: 18px 0;
            border-bottom: 2px solid transparent;
        }

        .tab.active {
            color: #2563eb;
            border-bottom-color: #2563eb;
        }

        /* Jitsi Room Area */
        #classroom-viewport {
            flex: 1;
            background: #000;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }

        #jaas-container {
            width: 100%;
            height: 100%;
        }

        /* Welcome UI (Overlay within the viewport) */
        #welcome-ui {
            position: fixed;
            z-index: 10;
            text-align: center;
            background: white;
            padding: 3rem;
            border-radius: 12px;
            box-shadow: 0 10px 15px rgba(0, 0, 0, 0.1);
        }

        button#join-btn {
            padding: 12px 30px;
            background: #2563eb;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1rem;
        }

        #classroom-viewport {
            flex: 1;
            background: #000;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: auto; /* Scroll if the window is too small for the ratio */
            padding: 20px;
        }

        #jaas-container {
            width: 100%;
            max-width: 1200px; /* Optional: cap the width */
            aspect-ratio: 16 / 9; /* MAINTAINS RATIO */
            background: #111;
            box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.5);
        }
    </style>
</head>
<body>

<div class="sidebar">
    <h3>Radixia LMS</h3>
    <div class="sidebar-nav">
        <div class="nav-item">Dashboard</div>
        <div class="nav-item">My Courses</div>
        <div class="nav-item">Assignments</div>
<!--        <div class="nav-item" id="join-btn">Join Session</div>-->
    </div>
</div>

<div class="main-content">
    <div class="header-tabs">
        <div class="tab active">Video Classroom</div>
        <div class="tab">Lesson Resources</div>
        <div class="tab">Class Chat</div>
    </div>

    <div id="classroom-viewport">
        <div id="welcome-ui">
            <h2>Alpha Batch 2026</h2>
            <p>The session is ready for you to join.</p>
            <button id="join-btn">Join Classroom</button>
            <div id="error-msg" style="color:red; margin-top:10px;"></div>
        </div>

        <div id="jaas-container"></div>
    </div>
</div>

<script src="https://8x8.vc/external_api.js"></script>

<script>
    const btn = document.getElementById('join-btn');
    const welcomeUi = document.getElementById('welcome-ui');
    const jitsiContainer = document.getElementById('jaas-container');
    const errorMsg = document.getElementById('error-msg');

    const sessionId = "019c1dc3-1f40-725b-a0dd-7a4e1dd37227";
    const BASE_URL = 'http://127.0.0.1:8000';

    btn.addEventListener('click', () => {
        btn.disabled = true;
        btn.innerText = "Joining...";

        fetch(`${BASE_URL}/api/v1/cohort-sessions/${sessionId}/join`, {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer YOUR_API_TOKEN',
                'Accept': 'application/json'
            }
        })
            .then(response => response.json())
            .then(res => {
                const meetingData = res.data;

                welcomeUi.style.display = 'none';

                const api = new JitsiMeetExternalAPI("8x8.vc", {
                    roomName: `${meetingData.appId}/${meetingData.room}`,
                    parentNode: jitsiContainer,
                    jwt: meetingData.jwt,
                    width: '100%',
                    height: '100%',
                    configOverwrite: {
                        subject: meetingData.subject,
                        startWithAudioMuted: true,
                        startWithVideoMuted: true,
                        disableInviteFunctions: true,
                        enableEndConference: true,
                        buttonsWithConfirmation: ['hangup'],

                        // ADDED MISSING OPTIONS HERE:
                        toolbarButtons: [
                            'microphone', 'camera', 'desktop', 'participants-pane',
                            'chat', 'raisehand', 'videoquality', 'fullscreen',
                            'settings', 'tileview', 'download', 'help', 'mute-everyone',
                            'mute-video-everyone', 'security', 'hangup'
                        ],
                        // This ensures buttons don't disappear into the "..." menu too early
                        toolbarConfig: {
                            initialTimeout: 20000,
                            alwaysVisible: false
                        }
                    },
                    interfaceConfigOverwrite: {
                        // Force the filmstrip to be on the right to save vertical space
                        VERTICAL_FILMSTRIP: true,
                    }
                });
            })
            .catch(err => {
                btn.disabled = false;
                btn.innerText = "Join Classroom";
                errorMsg.innerText = "Failed to connect. Is your API running?";
            });
    });
</script>
</body>
</html>