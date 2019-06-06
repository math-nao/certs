FROM neilpang/acme.sh:latest

WORKDIR /root/

RUN apk --no-cache add libidn jq \
  && mkdir certs

COPY scripts/* ./

CMD ["sh", "certs.sh"]