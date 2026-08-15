FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends clamav \
    && freshclam \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 dpps
WORKDIR /app
COPY . /app
RUN python -m pip install '.[service]'

USER dpps
EXPOSE 8080
CMD ["uvicorn", "dpps.api:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
