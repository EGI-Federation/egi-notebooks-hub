# Starting with the image used in helm jupyterhub
FROM jupyterhub/k8s-hub:1.2.0

USER root

COPY . /egi-notebooks-hub/

# install the hub extensions
# hadolint ignore=DL3013
RUN pip3 install --no-cache-dir /egi-notebooks-hub

# Copy images to the right place so they are found
RUN cp -r /egi-notebooks-hub/static/* /usr/local/share/jupyterhub/static/

ARG NB_USER=jovyan
USER ${NB_USER}
