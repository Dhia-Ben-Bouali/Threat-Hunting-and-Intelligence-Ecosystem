function toggleSidebar() {
    const sidebar = document.getElementById("sidebar");
    sidebar.classList.toggle("closed");
  }
  
  function updateAlerts() {
    alert("Fetching latest alerts from the database...");
  }
  // Function to update the clock every second
    function updateClock() {
      const now = new Date();
      const hours = now.getHours().toString().padStart(2, '0');
      const minutes = now.getMinutes().toString().padStart(2, '0');
      const seconds = now.getSeconds().toString().padStart(2, '0');
      const timeString = `${hours}:${minutes}:${seconds}`;

      // Display the time in the #clock span
      document.getElementById("clock").textContent = timeString;
    }

    // Update the clock every second
    setInterval(updateClock, 1000);

    // Initial clock update
    updateClock();

    function toggleSidebar() {
      const sidebar = document.getElementById("sidebar");
      sidebar.classList.toggle("closed");
    }

    // Update statuses based on the alert data
function updateAlertInfo(isMaliciousFile, isSlackMessageSent, isPlaybookTriggered) {
    // Update malicious file status
    const maliciousFileStatus = document.getElementById('malicious-file-status');
    maliciousFileStatus.textContent = isMaliciousFile ? 'Malicious File Detected' : 'No Malicious File';
  
    // Update Slack message status
    const slackStatus = document.getElementById('slack-status');
    slackStatus.textContent = isSlackMessageSent ? 'Message Sent' : 'Message Pending';
  
    // Update playbook status
    const playbookStatus = document.getElementById('playbook-status');
    playbookStatus.textContent = isPlaybookTriggered ? 'Triggered' : 'Not Triggered';
  }
  
  // Example usage with sample data
  updateAlertInfo(true, true, false);
  

  function showAlertDetails(email) {
    document.getElementById('email-display').textContent = email;
  }
