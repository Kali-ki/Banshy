#!/bin/bash

# This script launch all the necessary resources 
# to deploy Banshy application on a Kubernetes cluster

# Works only with Minikube

kubectl apply -f mysql-db-secret.yaml
kubectl apply -f mysql-db-deployment.yaml
kubectl apply -f mysql-db-service.yaml
printf "\nWait for mysql-db to start\n\n"
sleep 5s
# Wait for mysql-db to start
kubectl wait --for=condition=ready pod -l app=mysql-db-container --timeout=5m

kubectl apply -f banshy-deployment.yaml
kubectl apply -f banshy-service.yaml
printf "\nWait for banshy to start\n\n"
sleep 5s
# Wait for banshy to start
kubectl wait --for=condition=ready pod -l app=banshy-container --timeout=5m


kubectl apply -f nginx-deployment.yaml
kubectl apply -f nginx-service.yaml
printf "\nWait for nginx to start\n\n"
sleep 5s
# Wait for nginx to start
kubectl wait --for=condition=ready pod -l app=nginx --timeout=2m

sleep 5s
# Open service outside the cluster
minikube service nginx-service

