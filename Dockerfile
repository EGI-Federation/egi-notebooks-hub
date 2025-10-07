# Starting with the image used in helm jupyterhub
FROM quay.io/jupyterhub/k8s-hub:4.4.1 AS base

ARG KRB5CC_VERSION=1.1.0
FROM base AS build
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    git \
    libkrb5-dev \
    pkg-config \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m builder
USER builder
WORKDIR /home/builder
RUN git clone -b "$KRB5CC_VERSION" https://gitlab.cesnet.cz/702/projekty/krb5-oidc2cc
WORKDIR /home/builder/krb5-oidc2cc
RUN pip3 install --no-cache-dir build \
 && python3 -m build \
 && pip3 install --no-cache-dir -r requirements-test.txt -e . \
 && for t in test-*.py; do ./"$t"; done

FROM base
USER root

# Do installation in 2 phases to cache dependendencies
COPY requirements.txt /egi-notebooks-hub/
COPY --from=build /home/builder/krb5-oidc2cc/dist/krb5cc-*.whl /tmp
RUN pip3 install --no-cache-dir -r /egi-notebooks-hub/requirements.txt \
 && pip3 install --no-cache-dir /tmp/krb5cc-*.whl \
 && rm -fv /tmp/krb5cc-*.whl

# Now install the code itself
COPY . /egi-notebooks-hub/
RUN pip3 install --no-cache-dir /egi-notebooks-hub

# Copy images to the right place so they are found
RUN cp -r /egi-notebooks-hub/static/* /usr/local/share/jupyterhub/static/

HEALTHCHECK --interval=5m --timeout=3s \
  CMD curl -f http://localhost:8000/hub/health || exit 1

ARG NB_USER=jovyan
USER ${NB_USER}
