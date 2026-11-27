# SekuScan agent image. The base is pinned to the Playwright release in
# requirements.lock, so the browser build matches the library.
FROM mcr.microsoft.com/playwright/python:v1.65.2-noble

COPY . /src
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -c /src/requirements.lock /src \
 && rm -rf /src
ENV PATH=/opt/venv/bin:$PATH

# Not root: the browser sandbox cannot run as root.
USER pwuser
ENTRYPOINT ["sekuscan-agent"]
