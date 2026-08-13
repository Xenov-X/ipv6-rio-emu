FROM python:3.12-alpine
RUN apk add --no-cache iproute2 && pip install --no-cache-dir scapy
COPY rio-agent.py /usr/local/bin/rio-agent.py
ENTRYPOINT ["python3", "-u", "/usr/local/bin/rio-agent.py"]
