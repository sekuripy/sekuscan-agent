# SekuScan agent image. The base is pinned to the Playwright release in
# requirements.lock, so the browser build matches the library.
FROM mcr.microsoft.com/playwright/python:v1.65.2-noble

COPY . /src
# The image has no venv module; its own Playwright is in the system Python.
RUN pip3 install --no-cache-dir --break-system-packages -c /src/requirements.lock /src \
 && rm -rf /src

# Not root: the browser sandbox cannot run as root.
USER pwuser
ENTRYPOINT ["sekuscan-agent"]
