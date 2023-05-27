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


### Verification Provider Configuration

As a verification provider we use Fractal.id <https://fractal.id/>

Provider could be configured with JSON configuration below:

```
    "verificationProvider": {
        "requestTokenUrl": "https://{{PUT_PUT_AUTH_FRACTAL_HOST_HERE}}/oauth/token",
        "requestUserUrl": "https://{{PUT_PUT_RESOURCE_FRACTAL_HOST_HERE}}/users/me",
        "clientId": "{{PUT_FRACTAL_CLIENT_ID_HERE}}",
        "clientSecret": "{{PUT_FRACTAL_CLIENT_SECRET_HERE}}"
    }
```

Configuration keys explanation:

*   `requestTokenUrl` - Url used to acquire user token with provided `authorization_code`. Host should be set using the `AUTH_DOMAIN` placeholder from `Fractal.id` docs. See more <https://docs.developer.fractal.id/production-and-staging-urls>
*   `requestUserUrl` - Url used to acquire user information by an access token. Host should be set using the `RESOURCE_DOMAIN` placeholder from `Fractal.id` docs. See more <https://docs.developer.fractal.id/production-and-staging-urls>
*   `clientId` - Client id from API info acquired after create of integration at `Fractal.id` client dashboard. See more <https://docs.developer.fractal.id/client-dashboard>
*   `clientSecret` - Client secret from API info acquired after create of integration at `Fractal.id` client dashboard. See more <https://docs.developer.fractal.id/client-dashboard>

## Docker

Build docker image
`docker build -t verification-oracle . &`

Prepare registry to be used with docker-compose
`docker run -d -p 5000:5000 --restart=always --name registry registry:2`

Tag previously built docker image
`docker tag verification-oracle:latest localhost:5000/verification-oracle`

Push built tag to registry
`docker push localhost:5000/verification-oracle:latest`

Pull & run docker image using docker-compose
`docker-compose pull && docker-compose --compatibility up -d`
