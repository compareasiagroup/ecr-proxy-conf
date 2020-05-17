
FROM golang:alpine as builder

ENV PATH /go/bin:/usr/local/go/bin:$PATH
ENV GOPATH /go

RUN	apk add --no-cache \
	ca-certificates

COPY . /go/src/github.com/compareasiagroup/ecr-proxy-conf

RUN set -x \
	&& apk add --no-cache --virtual .build-deps \
		git \
		gcc \
		libc-dev \
		libgcc \
		make \
	&& cd /go/src/github.com/compareasiagroup/ecr-proxy-conf \
	&& make static \
	&& mv ecr-proxy-conf /usr/bin/ecr-proxy-conf \
	&& apk del .build-deps \
	&& rm -rf /go \
	&& echo "Build complete."

FROM scratch

COPY --from=builder /usr/bin/ecr-proxy-conf /usr/bin/ecr-proxy-conf
COPY --from=builder /etc/ssl/certs/ /etc/ssl/certs

COPY conf-templates /conf-templates

ENTRYPOINT [ "ecr-proxy-conf" ]
CMD [ "loop" ]
