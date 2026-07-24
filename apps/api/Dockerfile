FROM ghcr.io/astral-sh/uv:0.11.16@sha256:440fd6477af86a2f1b38080c539f1672cd22acb1b1a47e321dba5158ab08864d AS uv

FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/workspace/apps/api/.venv/bin:$PATH"

COPY --from=uv /uv /uvx /bin/
WORKDIR /workspace

COPY apps/api/pyproject.toml apps/api/uv.lock apps/api/README.md ./apps/api/
WORKDIR /workspace/apps/api
RUN uv sync --frozen --no-dev --no-install-project

WORKDIR /workspace
COPY --chown=10001:10001 apps/api/app ./apps/api/app
COPY --chown=10001:10001 samples ./samples

WORKDIR /workspace/apps/api
RUN uv sync --frozen --no-dev \
    && groupadd --system --gid 10001 supplyguard \
    && useradd --system --uid 10001 --gid supplyguard --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin supplyguard \
    && mkdir -p /workspace/apps/api/data \
    && chown supplyguard:supplyguard /workspace/apps/api/data

USER supplyguard
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=2).read()"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
