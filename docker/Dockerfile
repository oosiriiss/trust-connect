# Building stage
FROM gcc:15.2.0 AS builder

RUN apt-get update 
RUN apt-get install -y cmake ninja-build 

WORKDIR /src

COPY . .

ARG TARGET_NAME

RUN echo "TARGET_NAME ======= ${TARGET_NAME}"

RUN cmake -B build -G Ninja -DBUILD_DOCS=OFF -DCOMPILE_TESTS=OFF -DENABLE_DEBUG_UTILS=OFF -DBUILD_CLIENT=OFF
RUN cmake --build build --target ${TARGET_NAME}

# Runtime stage

from ubuntu:24.04 AS runtime

RUN apt-get update  && apt-get install -y libstdc++6 libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ARG TARGET_NAME

COPY --from=builder /src/build/${TARGET_NAME} /app/appexe

CMD ["./appexe"]


