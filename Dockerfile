FROM golang:1.20-alpine AS builder

WORKDIR /app
COPY go.* ./
COPY *.go ./
RUN go build -o /go-forward-auth


FROM alpine

LABEL maintainer "quentinb69"

RUN apk update \
	&& apk upgrade --no-cache \
	&& apk add --no-cache openssl curl

WORKDIR /opt/gfa
COPY --from=builder /go-forward-auth ./gfa
COPY default.config.yml ./
COPY default.index.html ./
COPY entrypoint.sh /usr/local/bin

RUN chmod a+x /usr/local/bin/entrypoint.sh
RUN adduser -D gfa && chown -R gfa:gfa .

USER gfa:gfa

HEALTHCHECK --timeout=2s --start-period=5s \
	CMD curl -k https://localhost:8000/health

ENTRYPOINT [ "entrypoint.sh" ]

