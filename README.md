# ECR Proxy Conf

Conf generator for Nginx ECR Proxy

## Config

Environment Variables

| NAME | DESCRIPTION |
|------|-------------|
| `AWS_REGION`                | AWS Region (required)                                         |
| `AWS_ROLE_ARN`              | AWS Role ARN to assume (optional)                             |
| `CONF_HEALTH_PORT`          | listen port for Health Checks (default: `8080`)               |
| `CONF_PROXY_PORT`           | listen port for nginx (default: `80`)                         |
| `CONF_PROXY_RESOLVER`       | nginx resolver config (default: `8.8.8.8`)                    |
| `CONF_PROXY_CACHE_KEY`      | nginx caching config (default: `$uri`)                        |
| `CONF_PROXY_CACHE_MAX_SIZE` | nginx cache max size (default: `75g`                          |
| `CONF_PROXY_CACHE_PATH`     | nginx cache path (default: `/cache/cache`)                    |
| `CONF_TARGET_PATH`          | target path for nginx conf (default: `/etc/nginx/nginx.conf`) |
| `CONF_TEMPLATE_DIR`         | template dir for nginx conf (default: `./conf-templates`)     |
| `CONF_TEMPLATE_FILE`        | template for nginx conf (default: `nginx.tpl.conf`)           |
| `CONF_SSL_KEY_PATH`         | path to SSL key (default: `/etc/nginx/ssl/key.pem`)           |
| `CONF_SSL_CERT_PATH`        | path to SSL cert (default: `/etc/nginx/ssl/certificate.pem`)  |
| `CONF_INTERVAL`             | interval to fetch new ECR token (default: `6h`)               |
| `CONF_MAX_RETRIES`          | max retries when fetch ECR token failed (default: `10`)       |
| `LOG_LEVEL`                 | logrus log level                                              |

## Credits

Heavily based on:

- [Lotto24/aws-ecr-http-proxy](github.com/Lotto24/aws-ecr-http-proxy)
- [rancher/rancher-ecr-credentials](github.com/rancher/rancher-ecr-credentials)
