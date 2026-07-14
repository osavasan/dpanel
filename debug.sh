#!/bin/bash
export DB_PATH=/var/www/databases/dpanel.db 
echo "Starting dpanel in debug mode on port 8897..."
go run . -port 8897
