#!/bin/bash

# Configuration variables
LOCAL_DIR="/path/to/local/folder"          # Local directory to sync
REMOTE_USER="username"                     # Remote username
REMOTE_HOST="remote.server.com"            # Remote host
REMOTE_DIR="/path/to/remote/folder"        # Remote directory
LOG_FILE="/var/log/folder_sync.log"        # Log file location
SSH_KEY="$HOME/.ssh/id_rsa"                # SSH key location
LOCK_FILE="/tmp/folder_sync.lock"          # Lock file to prevent multiple instances
MAX_WAIT_TIME=300                          # Maximum wait time in seconds (5 minutes)

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Create log directory if it doesn't exist
LOG_DIR=$(dirname "$LOG_FILE")
if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR" || { echo "Failed to create log directory $LOG_DIR"; exit 1; }
fi

# Check if script is already running
if [ -f "$LOCK_FILE" ]; then
    PID=$(cat "$LOCK_FILE")
    if ps -p "$PID" > /dev/null; then
        log_message "Another sync process (PID: $PID) is already running. Waiting for 5 minutes before trying again..."
        sleep "$MAX_WAIT_TIME"
        
        # Check again after waiting
        if ps -p "$PID" > /dev/null; then
            log_message "Process still running after waiting. Exiting."
            exit 1
        else
            log_message "Previous process completed. Continuing with sync."
            rm -f "$LOCK_FILE"
        fi
    else
        log_message "Stale lock file found. Removing and continuing."
        rm -f "$LOCK_FILE"
    fi
fi

# Create lock file
echo $$ > "$LOCK_FILE" || { log_message "Failed to create lock file"; exit 1; }

# Make sure to remove lock file on exit
trap 'rm -f "$LOCK_FILE"; log_message "Sync process terminated"; exit' INT TERM EXIT

# Check if local directory exists
if [ ! -d "$LOCAL_DIR" ]; then
    log_message "Error: Local directory $LOCAL_DIR does not exist!"
    exit 1
fi

# Test SSH connectivity
log_message "Testing SSH connectivity to $REMOTE_HOST..."
if ! ssh -q -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE_USER@$REMOTE_HOST" exit; then
    log_message "Error: Cannot establish SSH connection to $REMOTE_HOST"
    exit 1
fi

# Check if remote directory exists, create if not
log_message "Checking if remote directory exists..."
if ! ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "test -d $REMOTE_DIR"; then
    log_message "Remote directory does not exist. Creating..."
    if ! ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "mkdir -p $REMOTE_DIR"; then
        log_message "Error: Failed to create remote directory $REMOTE_DIR"
        exit 1
    fi
fi

# Get file count before sync
BEFORE_COUNT=$(find "$LOCAL_DIR" -type f | wc -l)
log_message "Files in local directory before sync: $BEFORE_COUNT"

# Run rsync with stats
log_message "Starting rsync process..."
START_TIME=$(date +%s)

# Use rsync with -i (itemize changes) to capture detailed information
RSYNC_OUTPUT=$(rsync -avz --stats --itemize-changes -e "ssh -i $SSH_KEY" "$LOCAL_DIR/" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/" 2>&1)
RSYNC_STATUS=$?

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Check rsync exit status
if [ $RSYNC_STATUS -ne 0 ]; then
    log_message "Rsync failed with status $RSYNC_STATUS"
    log_message "Rsync error: $RSYNC_OUTPUT"
    exit 1
fi

# Parse rsync output to get statistics
log_message "Rsync completed with status $RSYNC_STATUS in $DURATION seconds"

# Extract and log statistics
FILES_TRANSFERRED=$(echo "$RSYNC_OUTPUT" | grep "Number of files transferred" | awk '{print $5}')
TOTAL_SIZE=$(echo "$RSYNC_OUTPUT" | grep "Total transferred file size" | awk '{print $5,$6}')
SENT=$(echo "$RSYNC_OUTPUT" | grep "Total bytes sent" | awk '{print $4,$5}')
RECEIVED=$(echo "$RSYNC_OUTPUT" | grep "Total bytes received" | awk '{print $4,$5}')

log_message "Files transferred: $FILES_TRANSFERRED"
log_message "Total size transferred: $TOTAL_SIZE"
log_message "Bytes sent: $SENT"
log_message "Bytes received: $RECEIVED"

# Log all changes
CHANGES=$(echo "$RSYNC_OUTPUT" | grep -E "^[><.][fd]" | wc -l)
log_message "Total changes (files/directories created, updated, or deleted): $CHANGES"

# Get file count after sync
AFTER_COUNT=$(ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "find $REMOTE_DIR -type f | wc -l")
log_message "Files in remote directory after sync: $AFTER_COUNT"

log_message "Sync completed successfully!"

# Remove lock file
rm -f "$LOCK_FILE"

exit 0
