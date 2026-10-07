FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MDMS_DB_PATH=/data/mdms.db

WORKDIR /srv

# 先装依赖以利用层缓存
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip check

# 应用、测试与验收脚本
COPY app ./app
COPY tests ./tests
COPY verify ./verify
COPY pytest.ini ./

RUN mkdir -p /data \
    && python -m compileall -q app verify tests \
    && adduser --system --uid 1001 mdms \
    && chown -R mdms /data /srv

USER mdms
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=10s --timeout=5s --start-period=8s --retries=5 \
    CMD python -c "import json,urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=4); sys.exit(0 if json.load(r)['status']=='ok' else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
