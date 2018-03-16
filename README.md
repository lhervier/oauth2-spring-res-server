# Implementing Oauth2 protected Rest services with Java/Spring

This is a sample application that show you how to implement a Spring @RestController that is using an oauth2 access token. It also setup the environment so that it handles CORS requests.

This is a pure Spring implementation using the existing spring-security-oauth classes. But instead of using the provided RemoteTokenService, I have copied it so :

- it is compatible with a standard OAuth2 Introspection Endpoint (as defined in RFC 7662).
- it is compatible with Google Cloud (which is NOT compliant to RFC7662 !).
