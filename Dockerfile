FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . \
 # run as an unprivileged user, never as root
 && useradd --create-home scanner
USER scanner
# The scanner is a CLI: `docker run sentinel-scanner web https://my-site.example --i-own-this`
ENTRYPOINT ["sentinel-scan"]
CMD ["--help"]
