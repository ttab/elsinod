# Elsinod - Elephant single node helper

Elsinod is a helper service that acts as a dummy OIDC provider for a minikube environment built using [elephant Helm charts](https://github.com/ttab/helm-elib). It also bootstraps Postgres with service databases and schemas and creates buckets in Minio.

## Minikube

Build custom images into minikube by:

``` shellsession
eval $(minikube docker-env)
docker build . -t ghcr.io/ttab/elsinod:v0.0.0
```

## DNS

For local testing i configured ingress DNS by following this guide (all the way to step 4): https://minikube.sigs.k8s.io/docs/handbook/addons/ingress-dns/

We need to do step 4 "Configure in-cluster DNS server to resolve local DNS names inside cluster" otherwise applications won't be able to resolve the host of the endpoints specified in the elsinod OIDC configuration:

``` json
{
  "issuer": "https://elsinod.demo.ecms.test",
  "authorization_endpoint": "https://elsinod.demo.ecms.test/protocol/openid-connect/auth",
  "token_endpoint": "https://elsinod.demo.ecms.test/token",
```

## TLS

Set up TLS https://minikube.sigs.k8s.io/docs/tutorials/custom_cert_ingress/:

``` shellsession
mkcert demo.ecms.test "*.demo.ecms.test" "*.api.demo.ecms.test"
kubectl -n kube-system create secret tls mkcert --key demo.ecms.test+2-key.pem --cert demo.ecms.test+2.pem
```

Create a secret for the mkcert CA so that we can mount it in containers:

``` shellsession
kubectl create secret generic mkcert-ca --from-file=$HOME/.local/share/mkcert/rootCA.pem
```

This is needed for containers to communicate with elsinod without SSL errors.

### Bruno

To be able to use bruno with self signed certificates, configure the `$HOME/.local/share/mkcert/rootCA.pem` in the Bruno settings panel.

The access token renewal script uses the standard node fetch implementation rather than the one that Bruno uses for requests. Start bruno with NODE_EXTRA_CA_CERTS to get node to trust elsinod:

``` shellsession
$ export NODE_EXTRA_CA_CERTS=$HOME/.local/share/mkcert/rootCA.pem
$ bruno
```

You can, of course, set this for your shell so that both Bruno and other node apps trust your local mkcert from now on.
