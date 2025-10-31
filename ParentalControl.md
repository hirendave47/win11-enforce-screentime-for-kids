# ParentalControl.ps1 Notes

This solution uses two main components:
1.  **A PowerShell Script:** This script contains all the logic for checking the time, tracking screen usage, and initiating the shutdown.
2.  **Windows Task Scheduler:** This is the built-in Windows tool that will run the script automatically every 5 minutes in the background with system-level privileges, making it difficult for a standard user to stop.

---

### Part 1: The PowerShell Script

This script is designed to be robust and self-contained. It will create its own log file to track daily usage and automatically reset the counter each day.

**Key Features of the Script:**
*   **Time Check:** Shuts down if the current time is outside the 6:00 AM to 10:00 PM window.
*   **Screen Time Check:** Tracks active screen time (when the screen is not locked) and shuts down if the 4-hour daily limit is exceeded.
*   **Daily Reset:** Automatically resets the usage counter at midnight.
*   **Secure Logging:** Stores the usage log in `C:\ProgramData`, a protected system location that a standard child's account cannot modify.
*   **Graceful Warning:** Gives a 60-second warning with a custom message before shutting down, allowing a moment to save work.

### Part 2: Deployment Instructions

Follow these steps carefully on your child's laptop while logged in with your **Administrator account**.

#### Step 1: Save the PowerShell Script

1.  Open Notepad or a PowerShell editor (like VS Code or the PowerShell ISE).
2.  Copy the entire script from above and paste it into the editor.
3.  Save the file to a permanent location. A good choice is to create a folder in the root of the C: drive.
    *   Create a folder: `C:\Scripts`
    *   Save the file inside that folder as: `ParentalControl.ps1`
    *   **Important:** Ensure the file extension is `.ps1`, not `.txt`.

#### Step 2: Set PowerShell Execution Policy

By default, Windows prevents scripts from running. You need to allow it.

1.  Click the **Start Menu**, type `PowerShell`.
2.  Right-click on **Windows PowerShell** and select **Run as administrator**.
3.  In the blue PowerShell window, type the following command and press Enter:
    ```powershell
    Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
    ```
4.  It may ask for confirmation. Type `Y` and press Enter.
5.  You can now close the PowerShell window.

#### Step 3: Create the Scheduled Task

This is the most critical step. It will make the script run automatically.

1.  Click the **Start Menu**, type `Task Scheduler`, and open it.
2.  In the right-hand "Actions" pane, click **Create Task...** (not "Create Basic Task").
3.  **General Tab:**
    *   **Name:** Give it a clear name, like `Child PC Usage Monitor`.
    *   Under "Security options", select **Run whether user is logged on or not**.
    *   Check the box for **Run with highest privileges**.
    *   Configure for: **Windows 11**.

    

4.  **Triggers Tab:**
    *   Click **New...**.
    *   Begin the task: **On a schedule**.
    *   Settings: **Daily**.
    *   Start time: You can set it for today, e.g., `6:00:00 AM`.
    *   Check the box for **Repeat task every:** and select **5 minutes** from the dropdown.
    *   For a duration of, select **Indefinitely**.
    *   Click **OK**.

    

5.  **Actions Tab:**
    *   Click **New...**.
    *   Action: **Start a program**.
    *   Program/script: `powershell.exe`
    *   Add arguments (optional): This is very important. Paste the following line:
        ```
        -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\ParentalControl.ps1"
        ```
    *   Click **OK**.

    

6.  **Conditions Tab:**
    *   You can leave most of these as default. Ensure **Start the task only if the computer is on AC power** is **UNCHECKED** if you want it to work on battery too.

7.  **Settings Tab:**
    *   Ensure **Allow task to be run on demand** is checked.
    *   For "If the task is already running, then the following rule applies:", select **Do not start a new instance**.
    *   Click **OK**.

8.  **Final Confirmation:** Windows will ask for your administrator password. Enter it to create the task.

#### Step 4: Test the Task

1.  In Task Scheduler, find the **Task Scheduler Library** on the left.
2.  Locate your new task (`Child PC Usage Monitor`) in the middle pane.
3.  Right-click on it and select **Run**.
4.  The script should execute immediately. To see if it worked, click on the **History** tab for the task. You should see events with "Action Completed" and details in the output. You can also check if the file `C:\ProgramData\ChildUsageTracker.log` was created.
5.  To test the shutdown, you can temporarily change the hours in the script to the current time, save it, and then run the task again. **Remember to change it back!**

---

### Important Considerations and Warnings

*   **Security:** This setup is effective for most children, but a technically savvy child might find ways to bypass it (e.g., by booting into a live USB OS, changing the system's clock, or if they know the admin password). **Keep your administrator password secret.**
*   **Fairness:** The 60-second warning gives your child a chance to save their work. Explain the rules to them so they understand why the computer is shutting down.
*   **Disabling the Script:** If you ever need to disable this control, simply open Task Scheduler, find the task, right-click it, and select **Disable** or **Delete**.
*   **Responsibility:** This tool is powerful. Use it responsibly. Monitor its effectiveness and have open conversations with your child about screen time.
