FROM golang:1.27-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG COMMIT=unknown
ARG VERSION=v0.2.0-dev

RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/redis-rest-api \
    ./cmd/redis-rest-api

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/redis-rest-api /redis-rest-api

EXPOSE 8081

USER nonroot:nonroot

ENTRYPOINT ["/redis-rest-api"]
