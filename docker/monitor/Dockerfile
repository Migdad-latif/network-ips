FROM python:3.11-slim

WORKDIR /app

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        libpcap-dev gcc && \
    apt-get clean

RUN pip install scapy psutil

COPY monitor.py .

CMD ["python", "monitor.py"]