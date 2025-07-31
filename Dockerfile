# Use official Go image
FROM golang:1.23.0-alpine

# Set working directory inside container
WORKDIR /app


# Copy source code into the container
COPY . .

# Download dependencies
RUN go mod tidy

# Build the app
RUN go build -o main main.go

# Expose the port (update based on each service)
EXPOSE 9999

# Run Cloudflared and then start the Go app
CMD ["./main"]
