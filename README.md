Comprehensive shell script for synchronisation of files from local to a remote server.

Here's an explanation of what the script does:

### Key Features

1. **Configuration Section**: Edit the variables at the top to set your local and remote paths, SSH credentials, and log file location.

2. **Process Management**:
   - Uses a lock file to prevent multiple instances running simultaneously
   - Waits 5 minutes and retries if another sync is already running
   - Cleans up stale lock files for robustness

3. **Initialization Tests**:
   - Checks if the local directory exists
   - Tests SSH connectivity to the remote server
   - Verifies/creates the remote directory if needed

4. **Execution & Logging**:
   - Runs rsync with detailed statistics
   - Tracks duration of the sync process
   - Parses and logs comprehensive statistics:
     - Number of files transferred
     - Total size transferred
     - Network usage (bytes sent/received)
     - Before/after file counts
     - Total changes made

### How to Use

1. Download the script and make it executable:
   ```bash
   chmod +x sync_script.sh
   ```

2. Edit the configuration variables at the top of the script to match your setup:
   - `LOCAL_DIR`: Your source directory
   - `REMOTE_USER`: Your SSH username
   - `REMOTE_HOST`: Your server hostname
   - `REMOTE_DIR`: Destination directory on the remote server
   - `SSH_KEY`: Path to your SSH key
   - `LOG_FILE`: Where to save logs

3. Run the script:
   ```bash
   ./sync_script.sh
   ```

4. For scheduled execution, you can add it to crontab.
