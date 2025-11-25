# syntax=docker/dockerfile:1

FROM golang:1.21-bookworm AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o messaging-app .

FROM gcr.io/distroless/static:nonroot
WORKDIR /app

COPY --from=builder /app/messaging-app /app/messaging-app
EXPOSE 8080

USER nonroot
ENTRYPOINT ["/app/messaging-app"]
