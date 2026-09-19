# One image for both roles in a seclogx cluster deployment -- the
# coordinator (wherever `seclogx ingest`/`seclogx hunt`/`seclogx search`
# etc. is run) and `seclogx worker`. The command passed at `docker run`/
# in docker-compose.yml/the Kubernetes Deployment picks the role; nothing
# in the image itself is role-specific.
#
# The installed main package includes native parsing and bundled detection data.
FROM rust:1-bookworm AS rust-toolchain

FROM python:3.12-slim-bookworm AS build

COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/opt/venv/bin:/usr/local/cargo/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv

WORKDIR /opt/seclogx

COPY . .

# Compile the bundled native extension during the image build. Runtime
# containers only need the installed environment.
RUN pip install --no-cache-dir ".[cluster]"

FROM python:3.12-slim-bookworm

ENV PATH=/opt/venv/bin:$PATH
WORKDIR /opt/seclogx

RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/venv /opt/venv

RUN python -c "from seclogx._native_backend import API_VERSION; from seclogx.config import BUNDLED_SIGMA_RULES_DIR; assert API_VERSION == 1; assert BUNDLED_SIGMA_RULES_DIR.is_dir()"

# No default case-root/volume is declared here -- mount one at
# `/opt/seclogx/cases` (or point --case-root elsewhere) if you want
# case.json/staging/logs to persist outside the container; the Parquet
# lake itself lives on the shared object storage configured via
# SECLOGX_STORAGE_BACKEND=s3, not on this image's filesystem, once
# cluster mode is on -- see deploy/README.md.

ENTRYPOINT ["seclogx"]
CMD ["--help"]
