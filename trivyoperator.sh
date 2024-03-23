#!/bin/bash

set -e

echo "Installing trivy-operator..."

kubectl create namespace trivy-system
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts
helm repo update

echo "Installing trivy-operator via helm in the namespace trivy-system"
helm install trivy-operator aqua/trivy-operator \
     --namespace trivy-system \
     --create-namespace \
     --version 0.21.1

echo "trivy-operator installed successfully........Paranoia is a good thing!"