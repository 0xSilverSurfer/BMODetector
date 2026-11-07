FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Dépendances d'abord (cache Docker) : scanner + cible de labo
COPY requirements-lab.txt requirements.txt ./
RUN pip install -r requirements-lab.txt

COPY bmo_detector.py judge.py reporter.py scoring.py ./
COPY payloads ./payloads
COPY target_lab ./target_lab

# Exécution sans privilèges root
RUN useradd --create-home --uid 1000 bmo && mkdir -p /app/reports && chown -R bmo:bmo /app
USER bmo

ENTRYPOINT ["python", "bmo_detector.py"]
CMD ["--help"]
