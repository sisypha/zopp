---
sidebar_position: 4
title: TLS Configuration
description: Secure your zopp deployment with TLS.
---

# TLS Configuration

This guide covers configuring TLS for secure communication between zopp clients and the server.

## Server TLS

Enable TLS on the server:

```bash
./zopp-server serve \
  --tls-cert /path/to/server.crt \
  --tls-key /path/to/server.key
```

Or via environment variables:

```bash
export ZOPP_TLS_CERT=/path/to/server.crt
export ZOPP_TLS_KEY=/path/to/server.key
./zopp-server serve
```

## Client Configuration

When connecting to a TLS-enabled server:

```bash
# With CA certificate (for self-signed)
zopp --server https://zopp.example.com:50051 --tls-ca-cert /path/to/ca.crt workspace list

# Or via environment variable
export ZOPP_SERVER=https://zopp.example.com:50051
export ZOPP_TLS_CA_CERT=/path/to/ca.crt
zopp workspace list
```

## Generating Certificates

### Self-Signed (Development)

```bash
# Generate CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
  -subj "/CN=zopp-ca"

# Generate server certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
  -subj "/CN=zopp.example.com"

cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = zopp.example.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -extfile server.ext
```

### Let's Encrypt (Production)

Use certbot or your preferred ACME client:

```bash
certbot certonly --standalone -d zopp.example.com
```

Then configure:

```bash
./zopp-server serve \
  --tls-cert /etc/letsencrypt/live/zopp.example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/zopp.example.com/privkey.pem
```

## Mutual TLS (mTLS)

For additional security, require client certificates:

```bash
./zopp-server serve \
  --tls-cert /path/to/server.crt \
  --tls-key /path/to/server.key \
  --tls-client-ca /path/to/client-ca.crt
```

Clients then need their own certificates:

```bash
zopp --server https://zopp.example.com:50051 \
  --tls-ca-cert /path/to/ca.crt \
  --tls-cert /path/to/client.crt \
  --tls-key /path/to/client.key \
  workspace list
```

## Docker with TLS

```bash
docker run -d \
  --name zopp-server \
  -p 50051:50051 \
  -v /path/to/certs:/certs:ro \
  ghcr.io/faiscadev/zopp-server:latest \
  serve --tls-cert /certs/server.crt --tls-key /certs/server.key
```

## Kubernetes with TLS

Use cert-manager for automatic certificate management:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: zopp-server-tls
spec:
  secretName: zopp-server-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - zopp.example.com
```

Then reference in your Helm values:

```yaml
server:
  tls:
    enabled: true
    existingSecret: zopp-server-tls
```

## Next Steps

- [Server Deployment](/self-hosting/server) - Deployment options
- [Database Setup](/self-hosting/database) - Configure storage
