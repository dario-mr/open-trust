# A real Jenkins for the Open Trust demo: the LTS controller, the pipeline plugins, configuration as
# code, and the docker CLI with buildx. Builds run on the controller and use the host's docker daemon.
FROM docker:28.5.2-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d AS docker
FROM jenkins/jenkins:2.580.2-lts-jdk21@sha256:74401de6a6f92e1afe1b02d1c8e3d0c33f263bfb5275dd8813f9150355f2367b
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx
# shortcut: plugin versions float with the update centre; pin them if the demo must be reproducible
RUN jenkins-plugin-cli --plugins workflow-aggregator git configuration-as-code job-dsl credentials-binding plain-credentials
COPY casc.yaml /usr/share/jenkins/ref/casc.yaml
ENV CASC_JENKINS_CONFIG=/usr/share/jenkins/ref/casc.yaml
