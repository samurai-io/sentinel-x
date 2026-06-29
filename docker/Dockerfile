# Stage 1: Build the firewall binary
FROM ubuntu:22.04 AS builder

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libpthread-stubs0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -B build -S . && cmake --build build

# Stage 2: Minimal runtime image
FROM ubuntu:22.04

WORKDIR /app
COPY --from=builder /app/build/sentinel_x .

# Run the simulation engine by default
CMD ["./sentinel_x"]
