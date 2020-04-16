#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage : $0 <session_name> <machine_type>"
    exit 1
fi

session="$1"
machine="$2"

# set up tmux
tmux start-server

# create a new tmux session
tmux new-session -d -s $session -n $machine

# Select pane 1, set dir to avd-pipe/src
tmux selectp -t 1
tmux send-keys "cd ~/Projects/avd-pipe/src; clear" C-m

# Split pane 1 horizontal
tmux splitw -h
tmux send-keys "cd /opt/avd-pipe; clear; sudo watch -n1 cat session.json" C-m

# Select pane 2 and split vertically
tmux selectp -t 2
tmux splitw -v


# select pane 3, set to api root
tmux selectp -t 3
tmux send-keys "cd /opt/avd-pipe; sudo rm -rf /opt/avd-pipe/*; clear" C-m

sleep 2

# Select pane 1
tmux selectp -t 1
# tmux send-keys "sudo build/avd_${machine} config/conf.json" C-m

# create a new window called scratch
tmux new-window -t $session:2 -n src
tmux send-keys "cd ~/Projects/avd-pipe/src; vim" C-m

# return to main vim window
tmux select-window -t $session:$machine
#
# Finished setup, attach to the tmux session!
tmux attach-session -t $session
