FROM python:3.12-slim
# scapy resolves libpcap via ctypes find_library, which needs glibc's ldconfig;
# on musl it returns None and BPF filter compilation fails at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 libpcap0.8 \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir scapy
COPY rio-agent.py /usr/local/bin/rio-agent.py
ENTRYPOINT ["python3", "-u", "/usr/local/bin/rio-agent.py"]
