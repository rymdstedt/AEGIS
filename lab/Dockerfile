FROM python:3.12-alpine

WORKDIR /opt/aegis-vulnlab
COPY vulnerable_app.py ./vulnerable_app.py

ENV AEGIS_LAB_CONTAINER=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 65534:65534
EXPOSE 18080
ENTRYPOINT ["python3", "/opt/aegis-vulnlab/vulnerable_app.py", "--port", "18080"]
