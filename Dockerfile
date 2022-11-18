FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-okta"]
COPY baton-okta /