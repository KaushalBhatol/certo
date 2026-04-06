docker build and push commands

`docker build -t bhatol/certo:latest -t bhatol/certo:v1.0 .`
`docker push bhatol/certo --all-tags`

## For both platform

```
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t bhatol/certo:latest \
  -t bhatol/certo:v1.0 \
  --push .
```
