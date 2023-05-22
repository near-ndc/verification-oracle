# verification-oracle

User verification oracle for SBT issuer.

## Configuration

All default configuration is available in `config/default.json` file.
To override these settings, create a `config/local.jsom` file.

### Credentials

Use `near generate-key i-am-human-credentials --networkId mainnet` to generate new credentials.
The above command will create a file `~/.near-credentials/mainnet/i-am-human-credentials.json` with required private key.

The `private_key` property from a resulting file could be either passed with environment variable `SIGNING_KEY` or set via configuration file as:

```
  "signer": {
    "credentials": {
      "signingKey": "{{PUT_PRIVATE_KEY_HERE}}"
    }
  }
```

The public key generated in a file `~/.near-credentials/mainnet/i-am-human-credentials.json` is in wrapped format.
If the ed25519 base64 encoded public key required (e.g. for i-am-human near contract), it could be obtained after service start from
an output (search for text `ED25519 public key (base64 encoded):`)

## Docker

Build docker image
`docker build -t verification-oracle . &`

Prepare registry to be used with docker-compose
`docker run -d -p 5000:5000 --restart=always --name registry registry:2`

Tag previously built docker image
`docker tag verification-oracle:latest localhost:5000/verification-oracle`

Push built tag to registry
`docker push localhost:5000/verification-oracle`

Pull & run docker image using docker-compose
`docker-compose pull && docker-compose --compatibility up -d`
