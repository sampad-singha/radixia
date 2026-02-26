<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LMS Classroom - Moderator</title>
    <style>
        body { font-family: sans-serif; margin: 0; display: flex; height: 100vh; background: #f0f2f5; }
        .main-content { flex: 1; display: flex; flex-direction: column; position: relative; }
        #classroom-viewport { flex: 1; background: #000; display: flex; align-items: center; justify-content: center; padding: 20px; position: relative; }
        #jaas-container { width: 100%; max-width: 1200px; aspect-ratio: 16/9; background: #111; }
        #welcome-ui { position: absolute; background: white; padding: 3rem; border-radius: 12px; text-align: center; }
        button { padding: 12px 24px; font-size: 1rem; cursor: pointer; }
        #end-class-btn { display:none; position:absolute; right:20px; top:20px; background:#dc2626; color:white; border:none; border-radius:6px; }
    </style>
</head>
<body>

<div class="main-content">
    <div id="classroom-viewport">
        <div id="welcome-ui">
            <h2>Moderator Classroom</h2>
            <p>Session is ready. Join as moderator.</p>
            <button id="join-btn">Start Classroom</button>
            <div id="error-msg" style="color:red; margin-top:10px;"></div>
        </div>
        <div id="jaas-container"></div>
        <button id="end-class-btn">End Class For Everyone</button>
    </div>
</div>

<script src="https://8x8.vc/external_api.js"></script>
<script>
    const joinBtn = document.getElementById('join-btn');
    const welcomeUi = document.getElementById('welcome-ui');
    const jitsiContainer = document.getElementById('jaas-container');
    const endClassBtn = document.getElementById('end-class-btn');

    const sessionId = "019c995b-612b-7006-8063-9e35e93a78cf";
    const BASE_URL = "http://127.0.0.1:8000";
    let api = null;
    let participants = [];

    joinBtn.addEventListener('click', async () => {
        joinBtn.disabled = true;
        joinBtn.innerText = "Joining...";

        try {
            const res = await fetch(`${BASE_URL}/api/v1/cohort-sessions/${sessionId}/join`, {
                method: "POST",
                headers: {
                    "Authorization": "Bearer 1|xD2MGgAd9yPGPg5IXVSR02Sw1u9gIovGsTBseysYc372090f",
                    "Accept": "application/json"
                }
            });

            if (!res.ok) throw new Error("Failed to fetch join data.");

            const { data: meetingData } = await res.json();

            welcomeUi.style.display = "none";

            api = new JitsiMeetExternalAPI("8x8.vc", {
                roomName: `${meetingData.appId}/${meetingData.room}`,
                parentNode: jitsiContainer,
                jwt: meetingData.jwt,
                width: "100%",
                height: "100%",
                configOverwrite: {
                    subject: meetingData.subject,
                    startWithAudioMuted: true,
                    startWithVideoMuted: true,
                    disableInviteFunctions: true,
                    enableEndConference: true,
                    buttonsWithConfirmation: ["hangup"],
                    toolbarButtons: [
                        "microphone", "camera", "desktop", "participants-pane",
                        "chat", "raisehand", "videoquality", "fullscreen",
                        "settings", "tileview", "download", "help",
                        "mute-everyone", "mute-video-everyone", "security", "hangup"
                    ],
                },
                interfaceConfigOverwrite: {
                    VERTICAL_FILMSTRIP: true,
                }
            });

            // Track connected participants
            api.addEventListener("participantJoined", ({ id }) => {
                if (!participants.includes(id)) {
                    participants.push(id);
                }
            });

            api.addEventListener("participantLeft", ({ id }) => {
                participants = participants.filter(pid => pid !== id);
            });

            // Show End Class button for moderator
            if (meetingData.is_moderator) {
                endClassBtn.style.display = "block";
                endClassBtn.addEventListener("click", handleEndClass);
            }

        } catch (err) {
            joinBtn.disabled = false;
            joinBtn.innerText = "Start Classroom";
            document.getElementById("error-msg").innerText = err.message;
        }
    });

    function handleEndClass() {
        if (!confirm("End class for all participants?")) return;

        // Kick others
        participants.forEach(pid => {
            api.executeCommand("kickParticipant", pid);
        });

        // Then hang up moderator
        api.executeCommand("hangup");

        // Optionally notify backend
        fetch(`${BASE_URL}/api/v1/cohort-sessions/${sessionId}/end`, {
            method: "POST",
            headers: {
                "Authorization": "Bearer YOUR_API_TOKEN",
                "Accept": "application/json"
            }
        });

        // Update UI
        endClassBtn.disabled = true;
        endClassBtn.innerText = "Class Ended";
    }
</script>

</body>
</html>
