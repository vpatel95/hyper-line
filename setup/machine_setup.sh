#!/bin/bash

if [[ $# -lt 2 ]]; then
    echo "Usage : $0 <session_name> <machine_type> [machine id]"
    exit 1
fi

session="$1"
machine="$2"

if [[ $machine == "worker" ]]; then
    if [[ $# -ne 3 ]]; then
        echo "Usage : machine_type worker requires machine_id"
        exit 1
    fi

    mid=$3
fi

# set up tmux
tmux start-server

# create a new tmux session
tmux new-session -d -s $session -n $machine

# Select pane 1, set dir to avd-pipe/src
tmux selectp -t 1
tmux send-keys "cd ~/Projects/avd-pipe/src" C-m

# Split pane 1 horizontal
tmux splitw -h
tmux send-keys "sudo rm -rf /opt/avd-pipe/*; cd /opt/avd-pipe; sudo watch -n1 cat session.json" C-m

# Select pane 2 and split vertically
tmux selectp -t 1
tmux splitw -v -p 80


# select pane 3, set to api root
tmux selectp -t 2
tmux send-keys "sudo truncate -s0 /var/log/avd_*; tail -f /var/log/avd_*.log" C-m

sleep 2

# Select pane 1
tmux selectp -t 1
if [[ $machine == "worker" ]]; then
    tmux send-keys "sudo build/avd_${machine} config/conf_w${mid}.json" C-m
else
    tmux send-keys "sudo build/avd_${machine} config/conf.json" C-m
fi

# create a new window called scratch
tmux new-window -t $session:2

# return to main vim window
tmux select-window -t $session:$machine
#
# Finished setup, attach to the tmux session!
tmux attach-session -t $session
