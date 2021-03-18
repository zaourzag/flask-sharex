FROM gitpod/workspace-full

# Install Redis.
RUN sudo apt-get update \
 && sudo apt-get install -y \
  redis-server mongodb \
 && sudo rm -rf /var/lib/apt/lists/*
ports:
  - port: 80
  - port: 443
# Install custom tools, runtimes, etc.
# For example "bastet", a command-line tetris clone:
# RUN brew install bastet
#
# More information: https://www.gitpod.io/docs/config-docker/
