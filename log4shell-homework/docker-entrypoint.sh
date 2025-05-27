#!/bin/sh

# Set JAVA_TOOL_OPTIONS environment variable.
# This is processed directly by the JVM itself, bypassing most shell/script issues.
export JAVA_TOOL_OPTIONS="-Dlog4j2.formatMsgNoLookups=false \
                          -Dcom.sun.jndi.rmi.object.trustURLCodebase=true \
                          -Dcom.sun.jndi.ldap.object.trustURLCodebase=true"

# Execute the Java application. The JVM will pick up JAVA_TOOL_OPTIONS.
exec java -jar /app.jar