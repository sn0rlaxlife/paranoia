# Build stage using the Chainguard Go image.
FROM cgr.dev/chainguard/go AS builder

# Set the working directory outside $GOPATH to support Go modules.
WORKDIR /app

# Copy go mod and sum files to download dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code into the container.
COPY . .

# Static build the Go app. Adjust the CGO_ENABLED flag as needed.
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o paranoia .

# Final stage using a minimal base image.
FROM alpine:3.18.6

# Copy the Go static executable from the build stage.
COPY --from=builder /app/paranoia /usr/local/bin/paranoia

# Run the compiled binary.
ENTRYPOINT ["/usr/local/bin/paranoia"]