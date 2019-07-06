FROM alpine

RUN apk -U --no-cache add \
  python3

RUN pip3 install --upgrade pip && \
    pip3 install --no-cache-dir \
    tornado \
    jinja2 \
    mako

CMD ["python3", "-c", "import tornado"]
