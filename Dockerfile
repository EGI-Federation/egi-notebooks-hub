# Starting with the image used in helm jupyterhub
FROM quay.io/jupyterhub/k8s-hub:3.2.1

USER root

# Do installation in 2 phases to cache dependendencies
COPY requirements.txt /egi-notebooks-hub/
RUN pip3 install --no-cache-dir -r /egi-notebooks-hub/requirements.txt

# Now install the code itself
COPY . /egi-notebooks-hub/
# hadolint ignore=DL3013
RUN pip3 install --no-cache-dir /egi-notebooks-hub

# Copy images to the right place so they are found
RUN cp -r /egi-notebooks-hub/static/* /usr/local/share/jupyterhub/static/

HEALTHCHECK --interval=5m --timeout=3s \
  CMD curl -f http://localhost:8000/hub/health || exit 1

ARG NB_USER=jovyan
USER ${NB_USER}
