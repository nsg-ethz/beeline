FROM envoyproxy/envoy-build-ubuntu:829698e9a36d266a1497fa222216a2ae91632ffe AS builder

ENV DEBIAN_FRONTEND noninteractive

RUN useradd -m -s /bin/bash newuser
WORKDIR /home/newuser
COPY . .
RUN chown -R newuser:newuser .
USER newuser

RUN git clone https://github.com/envoyproxy/envoy
WORKDIR /home/newuser/envoy
RUN bazel/setup_clang.sh /opt/llvm/
RUN bazel build --config=clang -c opt //source/exe:envoy-static --copt -g --define google_grpc=disabled --define exported_symbols=enabled --copt="-Wno-uninitialized" --cxxopt="-Wno-uninitialized"  --//source/extensions/wasm_runtime/v8:enabled=false

FROM ubuntu:20.04 AS envoy

RUN apt-get update && apt-get install -y libssl1.1

# copy envoy-static
COPY --from=builder /home/newuser/envoy/bazel-out/k8-opt/bin/source/exe/envoy-static /usr/local/bin/envoy

CMD ["envoy", "-c", "/etc/envoy/envoy.yaml"]
