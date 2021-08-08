[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Artifact HUB](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/certs)](https://artifacthub.io/packages/search?repo=certs)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://paypal.me/mathnao)

# A Let's Encrypt certificates manager for Kubernetes

This chart use the [acme.sh][acme-sh] script to generate Let's Encrypt certifcates with DNS validation only; it uses Kubernetes `Job` to get and renew certificates.

## Ingress annotations

Name  | Example | Description
------  | ----- | -----------
acme.kubernetes.io/enable | `"true"` | Enable `Certs` on this ingress when value is set to `"true"`.<br />Default value is empty.
acme.kubernetes.io/dns | `"dns_gd"` | Set the `acme.sh` `--dns` parameter: (see [https://github.com/Neilpang/acme.sh/wiki/dnsapi] for all `--dns` supported values).<br />Default value is empty.
acme.kubernetes.io/staging | `"true"` | Enable acme staging certificate validation when value is set to `"true"`.<br />Default value is empty.
acme.kubernetes.io/add-args | `"--keylength ec-256"` | Add more arguments to `acme.sh` command used to generate certificates.<br />Default value is empty.
acme.kubernetes.io/cmd-to-use | `"acme.sh -h"` | Replace the `acme.sh` command to use for generating certificates.<br />Default value is empty.

## Chart configuration

Parameter  | Default | Description
------  | ----- | -----------
image.registry | `mathnao` | Set the docker image registry to use.
image.repository | `certs` | Set the docker image repository to use.
image.tag | `tag` | Set the docker image tag to use.
schedule | `0 0,12 * * *` | Set the job schedule to run dns validation for certificate renew.
backoffLimit | `1` | Specify the number of retries before considering a job as failed.
activeDeadlineSeconds | `600` | Set an active deadline for terminatting a job.
ttlSecondsAfterFinished | `120` | Set a TTL for cleaning a job.
successfulJobsHistoryLimit | `3` | Specify how many completed jobs should be kept.
manageAllNamespaces | `false` | Whether or not `certs` should manage all namespaces for generating certificates.
debug | `false` | Display more logs when value is set to `"true"`.
failedJobsHistoryLimit | `1` | Specify how many failed jobs should be kept.
env | `[]` | List all environment variables needed to run a `acme.sh` dns validation for certificate renew.
secretResourceNames | `[]` | Limit Role/ClusterRole access to a list of secrets. This should be a list of tls secrets used by ingress resources.
demo.enabled | `false` | Enable a demo backend for test purpose.
demo.image | `mathnao/light-test-server` | Set the docker image to use for the demo backend
demo.service.type | `ClusterIP` | Set the service type for the demo backend
demo.service.port | `8080` | Set the service port for the demo backend
demo.secretName | `demo-ingress-cert` | Set the secret name for storing generated certificates
demo.hosts | `- "example.com"` | Set the list of your hosts to generate Let's Encrypt certificate

## Deployment example

1/ Have your Ingress Controller deployed and ready

2/ Register your ingress, for example:
```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: test-ingress
  annotations:
    acme.kubernetes.io/enable: "true"
    acme.kubernetes.io/dns: "dns_gd"
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  tls:
  - hosts:
    - sslexample.foo.com
    secretName: testsecret-tls
  rules:
  - host: sslexample.foo.com
    http:
      paths:
      - path: /
        backend:
          serviceName: service1
          servicePort: 80
```

3/ Install `Certs` chart:
```
# Add the `Certs` Helm repository
helm repo add certs https://math-nao.github.io/certs/charts

# Update your local Helm chart repository cache
helm repo update

# Install the `Certs` Helm chart in the same namespace than your ingresses
helm install \
  --name certs \
  --namespace app \
  --values values.yaml \
  certs/certs
```

`values.yaml` file may content for example:
```
# schedule a Kubernetes Job twice a day, certificate is renewed only if it is going to expire soon
schedule: "0 2,14 * * *"

# add all necessary environment variables for acme.sh dns validation
# see https://github.com/Neilpang/acme.sh/wiki/dnsapi
env:
- name: GD_Key
  value: XXXX
- name: GD_Secret
  value: XXXX
```

4/ Visit `https://sslexample.foo.com` webpage, you should have a valid Let's Encrypt certificate

## Acknowledgments
acme.sh: https://github.com/Neilpang/acme.sh

## License
This code is distributed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0), see LICENSE for more information.

## Donates
Your donation helps to maintain `Certs`:

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://paypal.me/mathnao)

[acme-sh]: https://github.com/Neilpang/acme.sh
