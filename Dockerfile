FROM node:24-bookworm-slim AS node-runtime

FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node-runtime /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
    binutils file tshark tesseract-ocr libzbar0

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src/agent/ /app/
COPY src/runtime/pi/ /app/runtime/pi/
RUN cd /app/runtime/pi && npm ci --omit=dev --no-audit --no-fund
COPY src/skills/ /skills/
COPY knowledge-base/ /knowledge-base/
COPY ctfy_entrypoint.py /app/ctfy_entrypoint.py

ENTRYPOINT ["python3", "/app/ctfy_entrypoint.py"]
