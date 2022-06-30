# Build Stage
FROM ghcr.io/evanrichter/cargo-fuzz:latest as builder

## Add source code to the build stage.
ADD . /src
WORKDIR /src

RUN echo building instrumented harnesses && \
    bash -c "pushd daemon/fuzz && cargo +nightly -Z sparse-registry fuzz build && popd" && \
    mv daemon/fuzz/target/x86_64-unknown-linux-gnu/release/bgp_decode /bgp_decode && \
    mv daemon/fuzz/target/x86_64-unknown-linux-gnu/release/rpki_decode /rpki_decode && \
    echo done

RUN echo building non-instrumented harnesses && \
    export RUSTFLAGS="--cfg fuzzing -Clink-dead-code -Cdebug-assertions -C codegen-units=1" && \
    bash -c "pushd daemon/fuzz && cargo +nightly -Z sparse-registry build --release && popd" && \
    mv daemon/fuzz/target/release/bgp_decode /bgp_decode_no_inst && \
    mv daemon/fuzz/target/release/rpki_decode /rpki_decode_no_inst && \
    echo done

# Package Stage
FROM rustlang/rust:nightly

COPY --from=builder /bgp_decode /bgp_decode_no_inst /
COPY --from=builder /rpki_decode /rpki_decode_no_inst /
