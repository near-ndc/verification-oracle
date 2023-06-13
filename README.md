# verification-oracle

User verification oracle for SBT issuer.


## Prerequisites

Installed `nginx` with valid certificates for `HTTPS` protocol


## Setup

Setup `nginx` to route https `POST` requests to locally bound ports.
Default ports for `production` env is 8080 and for `staging` env is 8081.
If not default ports required to be used, those should be updated in the configuration later.


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

### Google re-CAPTCHA configuration

We use re-CAPTCHA Enterprise to verify that request came from a human

Captcha client could be configured with JSON configuration below:

```
    "captcha": {
      "action": "homepage",
      "threshold": 0.5,
      "secret": "{{PUT_GOOGLE_CAPTCHA_SECRET_HERE}}
    }
```

Configuration keys explanation:

*   `action` - The page alias we want to verify captcha at, requests with `action` different from configured value will be denied
*   `threshold` - Google user's score threshold minimum to accept requests from. Score below this value will mean that user is most-likely a bot
*   `secret` - Secret required by Google to verify captcha for third-party clients

Sample of `*-secrets.json` configuration file:
```
{
    "verificationProvider": {
      "clientId": "{{SOME_CLIENT_ID_VALUE_HERE}}",
      "clientSecret": "{{SOME_CLIENT_SECRET_VALUE_HERE}}"
    },
    "signer": {
      "credentials": {
        "signingKey": "{{SOME_ED25519_BASE64_ENCODED_PRIVATE_KEY_HERE}}"
      }
    },
    "captcha": {
      "secret": "{{PUT_GOOGLE_CAPTCHA_SECRET_HERE}}
    }
}
```


## Deploy (GitHub Registry)

### Build

Use `GitHub Actions` script `.github/workflows/build_image.yml` to build images for `main` and `develop` branches to
be used accordingly for `production` and `staging` services

### Run

Pull & run docker image using docker-compose
`docker-compose pull && docker-compose --compatibility up -d`


## Deploy (Local Registry)

### Prerequisites

Prepare registry to be used with docker-compose
`docker run -d -p 5000:5000 --restart=always --name registry registry:2`

### Build

Build docker image
`docker build -t verification-oracle . &`

Tag previously built docker image
`docker tag verification-oracle:latest localhost:5000/verification-oracle`

Push built tag to registry
`docker push localhost:5000/verification-oracle:latest`

Update `docker-compose.yml` with images from local registry

### Run

Pull & run docker image using docker-compose
`docker-compose pull && docker-compose --compatibility up -d`
