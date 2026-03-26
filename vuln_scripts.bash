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