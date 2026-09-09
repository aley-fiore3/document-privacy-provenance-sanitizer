FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends clamav clamav-freshclam gosu \
    && freshclam \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 dpps
WORKDIR /app
COPY . /app
RUN python -m pip install '.[service]'
COPY scripts/docker-entrypoint.sh /usr/local/bin/dpps-entrypoint
RUN chmod 0755 /usr/local/bin/dpps-entrypoint \
    && chown -R dpps:dpps /app

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dpps-entrypoint"]
CMD ["serve"]
