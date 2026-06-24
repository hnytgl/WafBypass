FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/hnytgl/WafBypass"
LABEL org.opencontainers.image.description="WAF detection and authorized security testing toolkit"

WORKDIR /app

COPY . .
RUN python -m pip install --no-cache-dir .

ENTRYPOINT ["wafbypass"]
CMD ["--help"]
