#!/bin/bash
# Start monitor in background, then start web server
python monitor.py &
python server.py