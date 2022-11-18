# Starting with the image used in helm jupyterhub
FROM jupyterhub/k8s-hub:2.0.0

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

ARG NB_USER=jovyan
USER ${NB_USER}
