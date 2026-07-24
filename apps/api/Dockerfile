FROM ghcr.io/astral-sh/uv:0.11.16 AS uv

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/workspace/apps/api/.venv/bin:$PATH"

COPY --from=uv /uv /uvx /bin/
WORKDIR /workspace

COPY apps/api/pyproject.toml apps/api/uv.lock ./apps/api/
WORKDIR /workspace/apps/api
RUN uv sync --frozen --no-dev

WORKDIR /workspace
COPY apps/api/app ./apps/api/app
COPY samples ./samples

WORKDIR /workspace/apps/api
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
