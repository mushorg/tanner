FROM postgres:alpine

# Setup apt
RUN sed -i 's/dl-cdn/dl-2/g' /etc/apk/repositories && \
    apk -U --no-cache add postgresql && \
    apk -U --no-cache add postgresql-contrib && \
# Clean up
    rm -rf /tmp/* /var/tmp/* && \
    rm -rf /var/cache/apk/*

# Start redis
USER nobody:nobody
CMD systemctl start postgres
