source ./variables.sh

set -euo 

SESSION_NAME="run"

echo "Removing old certificate file at: '$TTP_CERT_PATH'"
rm -rf "$TTP_CERT_PATH"

echo "Launching session $SESSION_NAME"
tmux new-session -d -s $SESSION_NAME
echo "Session launched"
echo "Running TTP: '$TTP_EXE_CMD'"
tmux send-keys -t $SESSION_NAME "$TTP_EXE_CMD" C-m
echo "Waiting for ttp to create certificate file at: '$TTP_CERT_PATH'"

TIMEOUT=5
END_TIME=$(($SECONDS + TIMEOUT))

echo "Waiting max 5 seconds"
while [ ! -f "$TTP_CERT_PATH" ] && [ $SECONDS -lt $END_TIME ]; do
   echo "Waiting..."
   sleep 0.1
done

if [ ! -f "$TTP_CERT_PATH" ]; then
   echo "Couldn't find file at: $TTP_CERT_PATH"
   tmux kill-session -t "$SESSION_NAME"
   exit -1
fi

echo "Certificate created"
tmux split-window -h -t $SESSION_NAME
echo "Launching server with: '$SERVER_EXE_CMD'"
tmux send-keys -t $SESSION_NAME "$SERVER_EXE_CMD" C-m
echo "Launching client"
tmux split-window -v -t $SESSION_NAME
echo "Launching client with: $CLIENT_EXE_CMD'"
tmux send-keys -t $SESSION_NAME "$CLIENT_EXE_CMD" C-m



echo "Attaching session"
tmux attach-session -t $SESSION_NAME
