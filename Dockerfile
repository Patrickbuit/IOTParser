FROM gcc:14

RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    git \
    make \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace