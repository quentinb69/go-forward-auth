FROM golang:1.19-alpine AS builder

WORKDIR /app
COPY go.* ./
COPY *.go ./
RUN go build -o /go-forward-auth


FROM alpine

RUN apk update \
	&& apk upgrade --no-cache \
	&& apk add --no-cache openssl 

WORKDIR /opt/gfa
COPY --from=builder /go-forward-auth ./gfa
COPY default.config.yml ./
COPY default.index.html ./
COPY entrypoint.sh /usr/local/bin

RUN chmod a+x /usr/local/bin/entrypoint.sh
RUN adduser -D gfa && chown -R gfa:gfa .

USER gfa:gfa

ENTRYPOINT [ "entrypoint.sh" ]

