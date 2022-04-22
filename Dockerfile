FROM golang:1.16-alpine AS builder

WORKDIR /app

COPY go.* ./

#RUN go get github.com/knadh/koanf \
#	&& go get github.com/knadh/koanf/parsers/yaml \
#	&& go get github.com/knadh/koanf/providers/file \
#	&& go get github.com/gorilla/schema \
#	&& go get github.com/golang-jwt/jwt/v4

COPY data/* /data/
COPY src/*.go ./

RUN go build -o /go-forward-auth

FROM alpine

WORKDIR /

COPY --from=builder /go-forward-auth /go-forward-auth
COPY --from=builder /data/* /data/
#COPY --from=builder /app/go.* /data/

EXPOSE 8080

USER nobody:nobody

CMD [ "/go-forward-auth" ]

