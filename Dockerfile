# SekuScan agent image, for linux/amd64 and linux/arm64. The base is the
# Playwright release in requirements.lock, pinned by digest.
FROM mcr.microsoft.com/playwright/python:v1.65.2-noble@sha256:38dd67fc654b56b3cba611e4c8eb71cd33750e1cd29eea2a5dc00b484817a75f

COPY . /src
# The image has no venv module; its own Playwright is in the system Python.
RUN pip3 install --no-cache-dir --break-system-packages -c /src/requirements.lock /src \
 && rm -rf /src

# Not root: the browser sandbox cannot run as root.
USER pwuser
ENTRYPOINT ["sekuscan-agent"]
