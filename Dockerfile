FROM ghcr.io/nosial/ncc:dev AS plugin_builder
WORKDIR /plugin
COPY . /plugin
RUN ncc build --configuration release

FROM ghcr.io/nosial/federationlib:dev AS test

LABEL org.opencontainers.image.title="FederationAdGuard Test" \
      org.opencontainers.image.description="FederationServer Docker image with FederationAdGuard, for testing only" \
      org.opencontainers.image.vendor="Nosial"

# Installed by docker-entrypoint.sh through REQUIRE_PLUGINS (see docker-compose.yml)
COPY --from=plugin_builder /plugin/target/release/net.nosial.federation_adguard.ncc /opt/federationlib/plugins/net.nosial.federation_adguard.ncc
