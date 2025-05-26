# Use the appropriate compose command based on OS
DOCKER_COMPOSE := $(shell if [ "$(shell uname)" = "Darwin" ]; then echo "docker compose"; else echo "docker-compose"; fi)

# Define variables for common paths and image names
APP_DIR := app
INTRANET_APP_DIR := intranet
REQUIREMENTS_FILE := $(APP_DIR)/requirements.txt
FLASK_IMAGE_NAME := flask-app-1 # Assuming this is the name you'll build for your Flask app
KEYCLOAK_DB_IMAGE := postgres:16
KEYCLOAK_IMAGE := quay.io/keycloak/keycloak:latest
LDAP_IMAGE := osixia/openldap:1.5.0
PHPLDAPADMIN_IMAGE := osixia/phpldapadmin:0.9.0
INTRANET_IMAGE := intranet-app

.PHONY: up down reset logs check bandit-check pip-audit-check host-security scan build-flask-app

up:
	@echo "[*] Starting Homework 8: Mini-Enterprise IAM Stack..."
	@$(DOCKER_COMPOSE) up -d
	@echo "[*] Populating LDAP with seed data..."
	@cat seed.ldif | docker exec -i "$$($(DOCKER_COMPOSE) ps -q ldap)" ldapadd -x -D "cn=admin,dc=example,dc=com" -w adminpw
	@bash setup.sh

down:
	@$(DOCKER_COMPOSE) down -v

reset: down
	@docker system prune -f
	@make up
	@bash setup.sh

logs:
	@$(DOCKER_COMPOSE) logs -f

# --- Pre-build security checks ---
# This target runs static code analysis (Bandit) and dependency vulnerability checks (pip-audit).
# It's recommended to run these *before* building your application image.
check: bandit-check pip-audit-check

# Run Bandit for static security analysis on Python code.
# Using a specific Python image and installing Bandit on the fly.
# For larger projects or frequent runs, consider building a custom image with Bandit pre-installed
# to avoid repeated installation time.
bandit-check:
	@echo "Running code analysis with Bandit..."
	docker run --rm \
		-v "$(PWD)/$(APP_DIR)":/app \
		python:3.13-alpine sh -c "pip install --no-cache-dir bandit && bandit -r /app"
# /intranet is not a Python application, this scan is only for Python applications
#	docker run --rm \
		-v "$(PWD)/$(INTRANET_APP_DIR)":/intranet \
		python:3.13-alpine sh -c "pip install --no-cache-dir bandit && bandit -r /intranet"

# Run pip-audit for dependency vulnerability scanning.
# It checks your requirements.txt file for known vulnerabilities.
pip-audit-check:
	@echo "Running dependency check with pip-audit..."
	# Ensure requirements.txt exists and is accessible within the container
	@if [ ! -f "$(REQUIREMENTS_FILE)" ]; then \
		echo "Error: $(REQUIREMENTS_FILE) not found. Please ensure it exists."; \
		exit 1; \
	fi
	docker run --rm \
		-v "$(PWD)/$(APP_DIR)":/app \
		python:3.13-alpine sh -c "pip install --no-cache-dir pip-audit && pip-audit -r /app/requirements.txt"
# /intranet is not a Python application, this scan is only for Python applications
#	docker run --rm \
		-v "$(PWD)/$(INTRANET_APP_DIR)":/intranet \
		python:3.13-alpine sh -c "pip install --no-cache-dir pip-audit && pip-audit -r /intranet/requirements.txt"

# --- Host security check ---
# This target runs Docker Bench for Security to check the Docker daemon's configuration
# and host security best practices.
host-security:
	@echo "Running Docker Bench for Security..."
	# Mount the Docker socket to allow Docker Bench to inspect the Docker daemon.
	# This requires elevated privileges on the host.
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docker/docker-bench-security

# --- Image vulnerability scanning ---
# This target scans a *built* Docker image for known vulnerabilities using Docker Scout.
# Replace $(FLASK_IMAGE_NAME):latest with the actual name of your built application image.
scan-flask-app:
	@echo "Scanning Docker image for vulnerabilities with Docker Scout..."
	# Ensure the image is built before scanning. You might want to add a dependency here:
	# scan: build-flask-app
	docker scout recommendations flask-app:latest

# --- Image vulnerability scanning ---
# This target scans a *built* Docker image for known vulnerabilities using Docker Scout.
# Replace $(FLASK_IMAGE_NAME):latest with the actual name of your built application image.
scan-intranet-app:
	@echo "Scanning Docker image for vulnerabilities with Docker Scout..."
	# Ensure the image is built before scanning. You might want to add a dependency here:
	# scan: build-flask-app
	docker scout recommendations intranet-app:latest

# --- Optional: Build your Flask app image (if not already part of your CI/CD) ---
# This is a placeholder; you'd typically have a 'build' target for your application.
build-flask-app:
	@echo "Building Flask application image..."
	docker build -t flask-app:latest ./$(APP_DIR)

build-intranet-app:
	@echo "Building Flask application image..."
	docker build -t intranet-app:latest ./$(INTRANET_APP_DIR)
