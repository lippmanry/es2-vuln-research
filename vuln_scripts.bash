mkdir ~/vulnerable-node-app;

cat << 'EOF' > ~/vulnerable-node-app/pom.xml
            <project>
                <modelVersion>4.0.0</modelVersion>
                <groupId>com.ghost.scanner</groupId>
                <artifactId>test-app</artifactId>
                <version>1.0.0</version>
                <dependencies>
                <dependency>
                    <groupId>org.apache.logging.log4j</groupId>
                    <artifactId>log4j-core</artifactId>
                    <version>2.14.1</version>
                </dependency>
                </dependencies>
            </project>
EOF;

cat << 'EOF' > ~/vulnerable-node-app/id_rsa
		-----BEGIN RSA PRIVATE KEY-----
		MIIEpAIBAAKCAQEA75P+31ndbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6f
		bc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6f
		bc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6fbc6f
		-----END RSA PRIVATE KEY-----
EOF;

cat << 'EOF' > ~/vulnerable-node-app/requirements.txt
Django==2.2.4
flask==0.12.1
PyYAML==3.12
EOF;

cat << 'EOF' > ~/vulnerable-node-app/package-lock.json
{
    "name": "multi-vuln-app",
    "version": "1.0.0",
    "lockfileVersion": 2,
    "requires": true,
    "packages": {
        "": {
        "name": "multi-vuln-app",
        "version": "1.0.0",
        "dependencies": {
            "axios": "0.21.1",
            "express": "4.16.0",
            "lodash": "4.17.20"
        }
        },
        "node_modules/axios": {
        "version": "0.21.1"
        },
        "node_modules/express": {
        "version": "4.16.0"
        },
        "node_modules/lodash": {
        "version": "4.17.20"
        }
    }
}
EOF;