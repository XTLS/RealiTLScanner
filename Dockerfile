FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o RealiTLScanner .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /src/RealiTLScanner .
ENTRYPOINT ["./RealiTLScanner"]