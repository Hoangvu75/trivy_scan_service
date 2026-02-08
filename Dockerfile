# Trivy K8s manifest scan service
FROM alpine:3.19

RUN apk add --no-cache \
    git \
    curl \
    python3 \
    py3-pip \
    kubectl \
    helm

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Flask
RUN pip3 install --no-cache-dir flask

WORKDIR /app

COPY scan.sh /app/scan.sh
COPY app.py /app/app.py

RUN chmod +x /app/scan.sh

ENV PORT=8080
EXPOSE 8080

CMD ["python3", "/app/app.py"]
