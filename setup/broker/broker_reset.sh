#!/bin/ash

rabbitmqctl stop
rabbitmqctl reset
tmux kill-server
fuser -k 80/tcp

tmux new-session -d -s authenticator 'cd /authenticator && kodev build && kore -fc conf/authenticator.conf'
rabbitmq-server -detached > /dev/null 2>&1
