ECR_REPO:=thirdparty/ecr-proxy-conf
DOCKER_TAG:=$(ECR_REGISTRY_URL)/$(ECR_REPO):v0.1.0
GO_LDFLAGS_STATIC=-ldflags "-w $(CTIMEVAR) -extldflags -static"

.PHONY: build docker static docker/login push

build:
	go build -o build/ecr-proxy-conf

static:
	@echo "+ $@"
	CGO_ENABLED=0 go build \
		-tags "static_build" \
		${GO_LDFLAGS_STATIC} -o ecr-proxy-conf .

docker: Dockerfile
	docker build \
		-t $(DOCKER_TAG) .

docker/login:
	$$(aws ecr get-login --no-include-email --region $(ECR_REGION))

push: docker/login
	docker push $(DOCKER_TAG)
