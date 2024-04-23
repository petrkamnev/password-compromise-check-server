FROM gcr.io/bazel-public/bazel:6.4.0

WORKDIR /app

COPY WORKSPACE BUILD deps.bzl /app/
COPY cmd /app/cmd
COPY pkg /app/pkg

RUN bazel build //cmd/pccserver

ENV PCCSERVER_STORAGE /data

VOLUME ["/data"]

COPY --chmod=755 entrypoint.sh /app/

ENTRYPOINT ["/app/entrypoint.sh"]

CMD ["run-server"]
