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
FROM alpine:3.23.0

# Create a non-root user.
RUN adduser -D -g '' paranoia

# Create a directory for the app and change its ownership to the new user.
RUN mkdir /app && chown paranoia:paranoia /app

# Switch to the new user.
USER paranoia

# Switch to the /app directory.
WORKDIR /app

# Copy the Go static executable from the build stage.
COPY --from=builder /app/paranoia /app/paranoia

# Run the compiled binary.
ENTRYPOINT ["/app/paranoia"]