FROM golang:1.16-alpine AS builder

WORKDIR /app

COPY go.* ./

#RUN go get github.com/knadh/koanf \
#	&& go get github.com/knadh/koanf/parsers/yaml \
#	&& go get github.com/knadh/koanf/providers/file \
#	&& go get github.com/gorilla/schema \
#	&& go get github.com/golang-jwt/jwt/v4 \
#	&& go get golang.org/x/crypto/bcrypt \
#	&& go get github.com/fsnotify/fsnotify@v1.4.9

COPY data/index.html /data/
COPY data/config.example.yml /data/
COPY src/*.go ./

RUN go build -o /go-forward-auth

FROM alpine

# for timezone
RUN apk update \
	&& apk add --no-cache tzdata

WORKDIR /

COPY --from=builder /go-forward-auth /go-forward-auth
COPY --from=builder /data/* /data/
#COPY --from=builder /app/go.* /tmp/

USER nobody:nobody

CMD [ "/go-forward-auth" ]

