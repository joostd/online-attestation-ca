#!/bin/bash

[[ -f ../ca/user_ca.pub ]] || { echo start ca first; exit; }

cp ../ca/user_ca.pub .
docker build -t ssh-server .
docker run --detach -p 22:22 --name ssh_demo ssh-server

docker container logs ssh_demo -f

docker stop ssh_demo
docker rm ssh_demo
docker rmi ssh-server
