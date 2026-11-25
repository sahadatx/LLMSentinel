# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY sentinel ./sentinel
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels '.[enterprise,observability]'

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=build /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels \
    && groupadd --system --gid 10001 sentinel \
    && useradd --system --uid 10001 --gid sentinel --home-dir /app sentinel \
    && mkdir -p /app/.sentinel \
    && chmod 700 /app/.sentinel \
    && chown -R sentinel:sentinel /app
COPY --chown=sentinel:sentinel policies /app/policies
COPY --chown=sentinel:sentinel benchmarks/dataset_v1.jsonl /app/benchmarks/dataset_v1.jsonl
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=8s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2)"
CMD ["sentinel", "gateway", "--host", "0.0.0.0", "--policy", "/app/policies/production-recommended.yaml"]
