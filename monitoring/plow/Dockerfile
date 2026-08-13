FROM alpine:latest
COPY --from=ghcr.io/six-ddc/plow:latest /usr/bin/plow /usr/local/bin/plow
RUN apk add --no-cache ca-certificates curl
