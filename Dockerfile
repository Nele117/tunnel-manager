FROM cloudflare/cloudflared:latest AS connector
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data
COPY --from=connector /usr/local/bin/cloudflared /usr/local/bin/cloudflared
RUN groupadd -g 10001 tunnel && useradd -u 10001 -g tunnel -M -s /usr/sbin/nologin tunnel && mkdir /data /app && chown tunnel:tunnel /data /app
WORKDIR /app
COPY --chown=tunnel:tunnel app.py ./
COPY --chown=tunnel:tunnel static ./static
USER tunnel
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)" || exit 1
CMD ["python", "app.py"]
