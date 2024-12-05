FROM python:3.10-alpine

RUN pip install --no-cache-dir --upgrade pip

ARG DRIVER_PORT
ENV DRIVER_PORT ${DRIVER_PORT:-7139}
ARG NUM_PROCESSES
ENV NUM_PROCESSES ${NUM_PROCESSES:-4}

COPY whls/*.whl /whls/

RUN addgroup -S netconfdriver \
 && adduser -S netconfdriver -G netconfdriver -u 101 \
 && mkdir -p /var/netconfdriver \
 && chown -R netconfdriver:0 /var/netconfdriver \
 && chmod -R 775 /var/netconfdriver \
 && chown -R netconfdriver:0 /home/netconfdriver \
 && chmod -R 775 /home/netconfdriver \
 && apk add --no-cache bash binutils libc-dev \
 # These packages need to be installed so that we can install the Python dependencies.
 # We make this virtual so that we can remove them later
 && apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev openssl-dev python3-dev make git \
 && for i in /whls/ignition*.whl; do if [ "$i" != "/whls/ignition*.whl" ]; then pip install --no-warn-script-location "$i"; fi done \
 && for i in /whls/*.whl; do pip install "$i"; done \
 && apk del .build-deps gcc musl-dev libffi-dev openssl-dev python3-dev make git

USER netconfdriver
WORKDIR /home/netconfdriver

EXPOSE 7139

CMD if [ $SSL_ENABLED | tr [:upper:] [:lower:] == "true" ]; then SSL="--certfile /var/netconfdriver/certs/tls.crt --keyfile /var/netconfdriver/certs/tls.key" ; fi \
&& gunicorn -k uvicorn.workers.UvicornWorker --workers  $NUM_PROCESSES --bind [::]:$DRIVER_PORT $SSL "netconfdriver:create_wsgi_app()"
