FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PROMETHEUS_MULTIPROC_DIR=/tmp/multiproc

EXPOSE 8080

CMD ["sh", "-c", \
     "rm -rf ${PROMETHEUS_MULTIPROC_DIR}/* && mkdir -p ${PROMETHEUS_MULTIPROC_DIR} && \
exec gunicorn \
  --worker-class gthread \
  --workers 6 \
  --threads 32 \
  --bind 0.0.0.0:8080 \
  --timeout 120 \
  --graceful-timeout 30 \
  --keep-alive 10 \
  --log-level info \
  proxy:app"]