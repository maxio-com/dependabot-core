FROM ghcr.io/dependabot/dependabot-updater-core AS base

USER dependabot

# Set up bundler helpers (required for bundler ecosystem)
COPY --chown=dependabot:dependabot bundler/helpers /opt/bundler/helpers
RUN bash /opt/bundler/helpers/v2/build

# Cache-busting layer - uses latest code modification time to force rebuilds only when needed
ARG CODE_MODIFIED_TIME
RUN echo "Code modified: ${CODE_MODIFIED_TIME:-$(date +%s)}" > /tmp/cache-bust

# Final stage - copy from base and add fresh source files
FROM base AS final

# Copy the local scanner files in a fresh context
COPY --chown=dependabot:dependabot local_scanner $DEPENDABOT_HOME/local_scanner
COPY --chown=dependabot:dependabot common $DEPENDABOT_HOME/common
COPY --chown=dependabot:dependabot bundler $DEPENDABOT_HOME/bundler
COPY --chown=dependabot:dependabot updater $DEPENDABOT_HOME/dependabot-updater
