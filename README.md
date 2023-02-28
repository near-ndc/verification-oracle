# gooddollar-oracle
GoodDollar oracle for SBT issuer.

## Docker

Build docker image
`docker build -t gooddollar-oracle . &`

Prepare registry to be used with docker-compose
`docker run -d -p 5000:5000 --restart=always --name registry registry:2`

Tag previously built docker image
`docker tag gooddollar-oracle:latest localhost:5000/gooddollar-oracle`

Push built tag to registry
`docker push localhost:5000/gooddollar-oracle`

Pull & run docker image using docker-compose
`docker-compose pull && docker-compose --compatibility up -d`
