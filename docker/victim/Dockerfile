FROM python:3.11-slim

WORKDIR /app

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        libpcap-dev gcc && \
    apt-get clean

RUN pip install flask scapy psutil

COPY server.py .
COPY monitor.py .
COPY start.sh .
RUN chmod +x start.sh

CMD ["./start.sh"]