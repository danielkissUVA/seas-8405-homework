package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.apache.logging.log4j.LogManager; // For logging the version
import org.apache.logging.log4j.Logger; // For logging the version
import org.apache.logging.log4j.util.PropertiesUtil; // For logging the version

@SpringBootApplication // This is the main Spring Boot application class
public class Log4shellDemoApplication {

    private static final Logger logger = LogManager.getLogger(Log4shellDemoApplication.class); // Use logger for this class

    public static void main(String[] args) {
        // Log the Log4j version at startup
        String log4jVersion = PropertiesUtil.getProperties().getStringProperty("log4j2.version");
        if (log4jVersion == null) {
            Package log4jPackage = Package.getPackage("org.apache.logging.log4j");
            if (log4jPackage != null) {
                log4jVersion = log4jPackage.getImplementationVersion();
            }
        }
        logger.info("**************************************************");
        logger.info("Log4j 2 Version in use: {}", log4jVersion != null ? log4jVersion : "UNKNOWN/NOT LOG4J2");
        logger.info("**************************************************");

        SpringApplication.run(Log4shellDemoApplication.class, args);
    }
}