go mod tidy -v && go mod vendor && make && rm -rf sync.c1z;
export BATON_C1_API_HOST="c1dev.willgarrison.d2.ductone.com:2443";
export BATON_API_TOKEN="00BJ3FdoEQaZe30JfnhFMcDjHVvnIhF335mGYf47Pe"
export BATON_DOMAIN="integrator-6841118.okta.com"
export CLIENT_ID="adventurous-passenger-90765@c1dev.willgarrison.d2.ductone.com/ccc";
export CLIENT_SECRET="secret-token:conductorone.com:v1:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkIwd29IWHBlYXRVSnBoOGpoakV2T1BuSWZqdWVKZkdzTU5aN0dBMjVIZm8iLCJkIjoieXRPZHNiQ3UycWQ4V2RDWUNPMmk5V2pNT3VSTlR1VnFpcC0tcWg1V0wtWSJ9";
./dist/darwin_arm64/baton-okta --client-id="$CLIENT_ID" --client-secret="$CLIENT_SECRET";
