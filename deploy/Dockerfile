# One image for both roles in a seclogx cluster deployment -- the
# coordinator (wherever `seclogx ingest`/`seclogx hunt`/`seclogx search`
# etc. is run) and `seclogx worker`. The command passed at `docker run`/
# in docker-compose.yml/the Kubernetes Deployment picks the role; nothing
# in the image itself is role-specific.
#
# The whole repo is copied in (not just the built wheel) because the
# bundled Sigma rule set is located at runtime relative to the package's
# source checkout (see src/seclogx/config.py's REPO_ROOT/
# BUNDLED_SIGMA_RULES_DIR) -- the same "run from an editable install
# inside the checkout" requirement documented in
# docs/guides/01_getting_started.md applies here too.
FROM python:3.12-slim

WORKDIR /opt/seclogx

COPY . .

# --no-cache-dir keeps the image smaller; the project itself has very
# few runtime dependencies (see pyproject.toml) so this stays quick.
RUN pip install --no-cache-dir -e ".[cluster]"

# No default case-root/volume is declared here -- mount one at
# `/opt/seclogx/cases` (or point --case-root elsewhere) if you want
# case.json/staging/logs to persist outside the container; the Parquet
# lake itself lives on the shared object storage configured via
# SECLOGX_STORAGE_BACKEND=s3, not on this image's filesystem, once
# cluster mode is on -- see deploy/README.md.

ENTRYPOINT ["seclogx"]
CMD ["--help"]
