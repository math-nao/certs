FROM neilpang/acme.sh:latest

ENV CERTS_VERSION=2.1.2

WORKDIR /root/

RUN apk --no-cache add libidn jq \
  && mkdir certs

COPY scripts/* ./

CMD ["sh", "certs.sh"]