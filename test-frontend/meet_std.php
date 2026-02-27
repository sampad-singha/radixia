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
    <h3>Radixia LMS (Student)</h3>
    <div class="sidebar-nav">
        <div class="nav-item">Student Dashboard</div>
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

    const sessionId = "019c9ef0-f98e-73f8-81b6-37f4b337a975";
    const BASE_URL = 'http://127.0.0.1:8000';

    btn.addEventListener('click', () => {
        btn.disabled = true;
        btn.innerText = "Joining...";

        fetch(`${BASE_URL}/api/v1/cohort-sessions/${sessionId}/join`, {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer 4|PIy2xpA2egy6fGaClDgKa522qE09cnkgqZLtwdGva587eb04',
                'Accept': 'application/json'
            }
        })
            .then(async response => {
                if (!response.ok) {
                    const error = await response.json().catch(() => null);
                    throw new Error(error?.message || "Failed to join");
                }
                return response.json();
            })
            .then(res => {
                const meetingData = res.data;
                welcomeUi.style.display = 'none';

                // instantiate Jitsi API
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
                        toolbarButtons: [
                            'microphone', 'camera', 'desktop', 'participants-pane',
                            'chat', 'raisehand', 'videoquality', 'fullscreen',
                            'settings', 'tileview', 'download', 'help', 'hangup'
                        ],
                        toolbarConfig: {
                            initialTimeout: 20000,
                            alwaysVisible: false
                        }
                    },
                    interfaceConfigOverwrite: {
                        VERTICAL_FILMSTRIP: true,
                    }
                });

                // OPTIONAL: Track participants (for later kick logic)
                let participants = [];

                api.addEventListener('participantJoined', ({ id }) => {
                    if (!participants.includes(id)) {
                        participants.push(id);
                    }
                });

                api.addEventListener('participantLeft', ({ id }) => {
                    participants = participants.filter(pid => pid !== id);
                });

                // You *cannot* do a kick unless you're a moderator
                // If you *were* a moderator you'd do:
                // participants.forEach(pid => api.executeCommand('kickParticipant', pid));
            })
            .catch(err => {
                btn.disabled = false;
                btn.innerText = "Join Classroom";
                errorMsg.innerText = err.message;
            });
    });
</script>
</body>
</html>
