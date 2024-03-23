#!/bin/bash

set -e

echo "Installing trivy-operator..."

git clone --depth 1 --branch v0.19.1 https://github.com/aquasecurity/trivy-operator.git
cd trivy-operator

echo "Install the chart from a local directory...."
helm install trivy-operator ./deploy/helm \
     --namespace trivy-system \
     --create-namespace 

echo "trivy-operator installed successfully........Paranoia is a good thing!"