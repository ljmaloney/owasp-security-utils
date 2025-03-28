# **owasp-security-utils**
### About
A small library leveraging https://github.com/ESAPI/esapi-java-legacy to sanitize inputs before being processed by the application code. More 
information about ESAPI and OWASP can be found at https://owasp.org/www-project-enterprise-security-api/ and https://owasp.org/
respectively.

### Purpose
Use this library when you need to retrofit cross-site-scripting and other input security measures
into an existing codebase. This will enable application of input sanitization with minimal code 
changes to existing classes. 

### Usage
Follow the steps below to implement / add the input sanitization to your application:
1. Add the com.green.yp.security.filter.filter.XSSFilter to your configuration.
2. Create a copy of ESAPI.properties and validation.properties in the resources folder of your project




