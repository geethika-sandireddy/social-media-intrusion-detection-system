![Social Media Intrusion Detection System](https://raw.githubusercontent.com/geethika-sandireddy/social-media-intrusion-detection-system/master/[image-filename-here])
Social Media Intrusion Detection System

## Overview
This project is a Java-based social media intrusion detection system designed to monitor user authentication activity and detect suspicious or malicious behavior using rule-based security checks.

The system focuses on identifying common attack patterns such as brute force login attempts, SQL injection attempts, password spraying, and unusual login behavior. Detected security events are logged and can be viewed through an admin dashboard.


## Features
- Secure user registration and login
- Password hashing using industry-standard techniques
- Tracking of failed login attempts and account lockout
- Detection of common attacks:
  - SQL Injection attempts
  - Brute force attacks
  - Password spraying
  - Unusual login times
  - Multiple IP login attempts
- Stylometry-based behavioral analysis using writing patterns
- Security event logging and monitoring dashboard
- Admin view for logs and security statistics


## Tech Stack
- Java (Core Java, Swing for GUI)
- DBMS (SQL)
- Git & GitHub


## Project Structure
social-media-intrusion-detection-system/
│
├── src/
│ └── Intrusense.java
│
├── database/
│ └── setup.sql
│
└── README.md




## How It Works 
1. Users enroll with a username, password, and optional writing sample.
2. Passwords are securely hashed before storage.
3. During login, the system validates credentials and monitors behavior.
4. Login attempts are logged and analyzed using rule-based checks.
5. Suspicious activities are recorded as security events.
6. Admin users can view logs and security statistics through the dashboard.


## Database Design
The database schema supports:
- User authentication data
- Stylometry profiles for behavioral comparison
- Login attempt logs
- Security event logging

The SQL schema is available in the `database/setup.sql` file.


## Project Status
This project is currently under development. Future enhancements may include advanced anomaly detection techniques, improved scalability, and cloud deployment.


## Disclaimer
This project is developed for academic and learning purposes to demonstrate intrusion detection concepts and secure authentication practices.
