FROM neilpang/acme.sh:latest

ENV CERTS_VERSION=2.0.0

WORKDIR /root/

RUN apk --no-cache add libidn jq \
  && mkdir certs

COPY scripts/* ./

CMD ["sh", "certs.sh"]