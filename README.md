# Paranoia KSPM
Project Paranoia is a kubernetes security posture management tool in development by sn0rlaxlife
<img src="https://github.com/sn0rlaxlife/paranoia/blob/main/paranoia-logo.png" alt="Paranoia" width="400" height="400">

## Introduction ##
This project serves as a kubernetes security posture management tool written in Go, this uses the kubernetes native client to initiate controls such as validation across your cluster on the following best practices. Like many users that are new to ecosystem of microservices this serves as a human-prevention tool on deploying misconfigurations, areas of concern, elevated privileges.


## Updates as of June 2025 ##
This project is still in experimental phase and only to be used for development operations use at your own risk.

- Added functionality now exists to track pods, deployments, secrets, and clusters roles
```bash
./paranoia watch -w --watch-pods
./paranoia watch -w --watch-deployments
```bash

## Quick Start
To leverage this tool in your cluster run the following commands.
```bash
git clone https://github.com/sn0rlaxlife/paranoia.git && cd paranoia
```


<b> The Makefile checks if Trivy-operator is installed to run on CRD Checks </b>
Use of trivyoperator.sh (if this isn't installed run chmod +x trivyoperator.sh -> ./trivyoperator.sh
```bash
make build
```

Run a RBAC (Sanity check) by simply using the CLI syntax below
```bash
./paranoia rbac -r
```

Run a deployment check on labels in cluster to identify no labels on various deployments.
```bash
./paranoia deployment -c
```

Run Watcher to identify existing pods that are risky in nature this will annotate warnings
```bash
./paranoia watch --watch
```

Run checks to validate high valued roles are running and found in your cluster such as system:certificates.k8s.io, system:auth-delegator, system:aggregate-to-admin. This check will also run a scan on the Node to identify if HA is detected the default value for this is 3 nodes.
```bash
./paranoia check -c
```

Run a vulnerability report on a existing namespace this leverages the outbound to our trivy-operator and CRDs
```bash
./paranoia report --kubeconfig=<kube-config> -n <namespace>
```
