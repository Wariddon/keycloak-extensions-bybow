FROM quay.io/keycloak/keycloak:21.0.0

COPY rest-endpoint/target/dasniko.keycloak-rest-endpoint.jar /opt/keycloak/providers/authenticator.jar
COPY target/keycloak-user-group-based-password-policy-4.0.0.jar /opt/keycloak/standalone/deployments