#!/bin/sh
exec 2>&1
exec /usr/bin/python3 /home/app/server.py --hostname '*' --port 25
