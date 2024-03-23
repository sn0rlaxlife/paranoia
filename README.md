# Paranoia KSPM
Project Paranoia is a kubernetes security posture management tool in development by sn0rlaxlife
<img src="https://github.com/sn0rlaxlife/paranoia/blob/main/paranoia-logo.png" alt="Paranoia" width="400" height="400">

## Introduction ##
This project serves as a kubernetes security posture management tool written in Go, this uses the kubernetes native client to initiate controls such as validation across your cluster on the following best practices. Like many users that are new to ecosystem of microservices this serves as a human-prevention tool on deploying misconfigurations, areas of concern, elevated privileges.


## Quick Start
To leverage this tool in your cluster run the following commands.
<code>git clone https://github.com/sn0rlaxlife/paranoia.git && cd /paranoia</code>

<b> The Makefile checks if Trivy-operator is installed to run on CRD Checks </b>
<div> Use of trivyoperator.sh </div>
<code> make build </code>

Run a check by simply using the CLI syntax below
<code>./paranoia rbac -r</code>
