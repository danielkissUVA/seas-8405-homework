FROM python:3.13-alpine
# Explain: Upgraded python container from the earlier vulnerable 3.9 version to 3.13
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
# The above command RUN addgroup -S appgroup && adduser -S appuser -G appgroup creates a new system group named "appgroup" and a new system user named "appuser", and then adds "appuser" to the "appgroup".
# This is a crucial security step because it allows us to run the application process as a non-root user (appuser) inside the container (USER appuser instruction later in the Dockerfile).
# Running as non-root limits the potential damage if the application is compromised.
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER appuser
# Exlain: The HEALTHCHECK instruction in a Dockerfile tells the Docker Engine how to test if a container is still working.
# This is important for orchestration systems (like Docker Swarm or Kubernetes) to know when to restart a container that has become unhealthy, even if the main process is still technically running.
HEALTHCHECK --interval=30s --timeout=10s CMD curl -f http://localhost:5000/ || exit 1
CMD ["python", "-u", "app.py"]
