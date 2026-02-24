# HoneySAP Dockerfile for running HoneySAP

FROM ubuntu:22.04

MAINTAINER martin.gallo@gmail.com

# Install system packages
RUN apt-get update && apt-get install -y \
        git \
        python3-pip \
        python3-dev \
        build-essential \
        python3-yaml && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY . /opt/honeysap
WORKDIR /opt/honeysap

# Install prebuilt pysap (not yet published on PyPI)
COPY pysap/dist/pysap-0.1.20.dev0.tar.gz /tmp/pysap.tar.gz
RUN python3 -m pip install /tmp/pysap.tar.gz && \
    rm -f /tmp/pysap.tar.gz

# Install HoneySAP
RUN cd /opt/honeysap && \
    python3 -m pip install . && \
    rm -rf /tmp/* /var/tmp/*

EXPOSE 3299 8001

CMD ["/usr/local/bin/honeysap", "--config-file", "honeysap.yml"]
