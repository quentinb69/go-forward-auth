FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.* ./
COPY *.go ./
RUN go build -o /go-forward-auth


FROM alpine:3.22.2

LABEL maintainer "quentinb69"

RUN apk update \
	&& apk upgrade --no-cache \
	&& apk add --no-cache curl

WORKDIR /opt/gfa
COPY --from=builder /go-forward-auth ./gfa
COPY default.config.yml ./
COPY default.index.html ./

RUN adduser -D gfa && chown -R gfa:gfa .

USER gfa:gfa

HEALTHCHECK --timeout=2s --start-period=5s \
	CMD curl -k https://localhost:8000/health

CMD [ "/opt/gfa/gfa" ]
