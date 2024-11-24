create table vulnerability
(
    cve          varchar(255) not null
        primary key,
    published_at timestamp    not null,
    url          varchar(255),
    title        varchar(255),
    score        double precision,
    severity     varchar(255),
    description  text,
    solution     text
);

alter table vulnerability
    owner to postgres;

INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52169', '2024-11-24 08:08:56.643927', 'https://cve.circl.lu/cve/CVE-2023-52169', '7-Zip Heap Based Buffer Overflow Vulnerability', 8.2, 'Medium', 'The NtfsHandler.cpp NTFS handler in 7-Zip before 24.01 (for 7zz) contains an out-of-bounds read that allows an attacker to read beyond the intended buffer. The bytes read beyond the intended buffer are presented as a part of a filename listed in the file system image. This has security relevance in some known web-service use cases where untrusted users can upload files and have them extracted by a server-side 7-Zip process.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52168', '2024-11-24 08:08:56.643940', 'https://cve.circl.lu/cve/CVE-2023-52168', '7-Zip Heap Based Buffer Overflow Vulnerability', 8.4, 'Medium', 'The NtfsHandler.cpp NTFS handler in 7-Zip before 24.01 (for 7zz) contains a heap-based buffer overflow that allows an attacker to overwrite two bytes at multiple offsets beyond the allocated buffer size: buffer+512*i-2, for i=9, i=10, i=11, etc.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-39573', '2024-11-24 08:08:56.643941', 'https://cve.circl.lu/cve/CVE-2024-39573', 'Apache Hypertext Transfer Protocol Server (HTTP Server) Prior to 2.4.60 Multiple Security Vulnerabilities', 7.5, 'High', e'Potential SSRF in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to cause unsafe RewriteRules to unexpectedly setup URL\'s to be handled by mod_proxy.
Users are recommended to upgrade to version 2.4.60, which fixes this issue.', 'Security by Obscurity is not a solution to preventing SQL Injection. Rather than suppress error messages and exceptions, the application must handle them gracefully, returning either a custom error page or redirecting the user to a default page, without revealing any information about the database or the application internals. Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as SQL content. Keywords such as UNION, SELECT or INSERT must be filtered in addition to characters such as a single-quote('') or SQL-comments (--) based on the context in which they appear.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38476', '2024-11-24 08:08:56.643942', 'https://cve.circl.lu/cve/CVE-2024-38476', 'Apache Hypertext Transfer Protocol Server (HTTP Server) Prior to 2.4.60 Multiple Security Vulnerabilities', 9.8, 'High', e'Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerably to information disclosure, SSRF or local script execution via backend applications whose response headers are malicious or exploitable.

Users are recommended to upgrade to version 2.4.60, which fixes this issue.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38475', '2024-11-24 08:08:56.643945', 'https://cve.circl.lu/cve/CVE-2024-38475', 'Apache Hypertext Transfer Protocol Server (HTTP Server) Prior to 2.4.60 Multiple Security Vulnerabilities', 9.1, 'High', e'Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations that are permitted to be served by the server but are not intentionally/directly reachable by any URL, resulting in code execution or source code disclosure. 

Substitutions in server context that use a backreferences or variables as the first segment of the substitution are affected.  Some unsafe RewiteRules will be broken by this change and the rewrite flag "UnsafePrefixStat" can be used to opt back in once ensuring the substitution is appropriately constrained.', 'Design: Use input validation before writing to web log Design: Validate all log data before it is output');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38473', '2024-11-24 08:08:56.643946', 'https://cve.circl.lu/cve/CVE-2024-38473', 'Apache Hypertext Transfer Protocol Server (HTTP Server) Prior to 2.4.60 Multiple Security Vulnerabilities', 8.1, 'High', e'Encoding problem in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows request URLs with incorrect encoding to be sent to backend services, potentially bypassing authentication via crafted requests.
Users are recommended to upgrade to version 2.4.60, which fixes this issue.', 'Design: Use input validation before writing to web log Design: Validate all log data before it is output');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38472', '2024-11-24 08:08:56.643947', 'https://cve.circl.lu/cve/CVE-2024-38472', 'Apache Hypertext Transfer Protocol Server (HTTP Server) Prior to 2.4.60 Multiple Security Vulnerabilities', 7.5, 'High', e'SSRF in Apache HTTP Server on Windows allows to potentially leak NTLM hashes to a malicious server via SSRF and malicious requests or content 
Users are recommended to upgrade to version 2.4.60 which fixes this issue.  Note: Existing configurations that access UNC paths will have to configure new directive "UNCList" to allow access during request processing.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-34750', '2024-11-24 08:08:56.643949', 'https://cve.circl.lu/cve/CVE-2024-34750', 'Atlassian Confluence Data Center and Server Denial of Service (DoS) Vulnerability (CONFSERVER-97657)', 7.5, 'High', e'Improper Handling of Exceptional Conditions, Uncontrolled Resource Consumption vulnerability in Apache Tomcat. When processing an HTTP/2 stream, Tomcat did not handle some cases of excessive HTTP headers correctly. This led to a miscounting of active HTTP/2 streams which in turn led to the use of an incorrect infinite timeout which allowed connections to remain open which should have been closed.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M20, from 10.1.0-M1 through 10.1.24, from 9.0.0-M1 through 9.0.89.

Users are recommended to upgrade to version 11.0.0-M21, 10.1.25 or 9.0.90, which fixes the issue.

', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-24549', '2024-11-24 08:08:56.643950', 'https://cve.circl.lu/cve/CVE-2024-24549', 'Atlassian Confluence Data Center and Server Denial of Service (DoS) Vulnerability (CONFSERVER-95834, CONFSERVER-95835)', 7.5, 'High', e'Denial of Service due to improper input validation vulnerability for HTTP/2 requests in Apache Tomcat. When processing an HTTP/2 request, if the request exceeded any of the configured limits for headers, the associated HTTP/2 stream was not reset until after all of the headers had been processed.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M16, from 10.1.0-M1 through 10.1.18, from 9.0.0-M1 through 9.0.85, from 8.5.0 through 8.5.98.

Users are recommended to upgrade to version 11.0.0-M17, 10.1.19, 9.0.86 or 8.5.99 which fix the issue.

', 'Security by Obscurity is not a solution to preventing SQL Injection. Rather than suppress error messages and exceptions, the application must handle them gracefully, returning either a custom error page or redirecting the user to a default page, without revealing any information about the database or the application internals. Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as SQL content. Keywords such as UNION, SELECT or INSERT must be filtered in addition to characters such as a single-quote('') or SQL-comments (--) based on the context in which they appear.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-23672', '2024-11-24 08:08:56.643951', 'https://cve.circl.lu/cve/CVE-2024-23672', 'Atlassian Confluence Data Center and Server Denial of Service (DoS) Vulnerability (CONFSERVER-95834, CONFSERVER-95835)', 6.3, 'High', e'Denial of Service via incomplete cleanup vulnerability in Apache Tomcat. It was possible for WebSocket clients to keep WebSocket connections open leading to increased resource consumption.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M16, from 10.1.0-M1 through 10.1.18, from 9.0.0-M1 through 9.0.85, from 8.5.0 through 8.5.98.

Users are recommended to upgrade to version 11.0.0-M17, 10.1.19, 9.0.86 or 8.5.99 which fix the issue.

', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-44487', '2024-11-24 08:08:56.643951', 'https://cve.circl.lu/cve/CVE-2023-44487', 'Microsoft HTTP/2 Protocol Distributed Denial of Service (DoS) Vulnerability', 7.5, 'High', 'The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-46589', '2024-11-24 08:08:56.643952', 'https://cve.circl.lu/cve/CVE-2023-46589', 'Dell NetWorker Multiple Third-party Component Vulnerabilities (DSA-2024-208)', 7.5, 'High', e'Improper Input Validation vulnerability in Apache Tomcat.Tomcat from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through 10.1.15, from 9.0.0-M1 through 9.0.82 and from 8.5.0 through 8.5.95 did not correctly parse HTTP trailer headers. A trailer header that exceeded the header size limit could cause Tomcat to treat a single 
request as multiple requests leading to the possibility of request 
smuggling when behind a reverse proxy.

Users are recommended to upgrade to version 11.0.0-M11 onwards, 10.1.16 onwards, 9.0.83 onwards or 8.5.96 onwards, which fix the issue.

', 'Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting Use web servers that employ a tight HTTP parsing process');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-29510', '2024-11-24 08:08:56.643953', 'https://cve.circl.lu/cve/CVE-2024-29510', 'Artifex Ghostscript Multiple Vulnerabilities (gs10.03.1)', 6.3, 'High', 'Artifex Ghostscript before 10.03.1 allows memory corruption, and SAFER sandbox bypass, via format string injection with a uniprint device.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-33871', '2024-11-24 08:08:56.643954', 'https://cve.circl.lu/cve/CVE-2024-33871', 'Artifex Ghostscript Multiple Vulnerabilities (gs10.03.1)', 8.8, 'High', 'An issue was discovered in Artifex Ghostscript before 10.03.1. contrib/opvp/gdevopvp.c allows arbitrary code execution via a custom Driver library, exploitable via a crafted PostScript document. This occurs because the Driver parameter for opvp (and oprp) devices can have an arbitrary name for a dynamic library; this library is then loaded.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-33870', '2024-11-24 08:08:56.643955', 'https://cve.circl.lu/cve/CVE-2024-33870', 'Artifex Ghostscript Multiple Vulnerabilities (gs10.03.1)', 6.3, 'High', 'An issue was discovered in Artifex Ghostscript before 10.03.1. There is path traversal (via a crafted PostScript document) to arbitrary files if the current directory is in the permitted paths. For example, there can be a transformation of ../../foo to ./../../foo and this will grant access if ./ is permitted.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-29133', '2024-11-24 08:08:56.643955', 'https://cve.circl.lu/cve/CVE-2024-29133', 'Atlassian Confluence Data Center and Server Multiple Security Vulnerabilities (CONFSERVER-95942, CONFSERVER-95943, CONFSERVER-95975, CONFSERVER-95974)', 5.4, 'High', e'Out-of-bounds Write vulnerability in Apache Commons Configuration.This issue affects Apache Commons Configuration: from 2.0 before 2.10.1.

Users are recommended to upgrade to version 2.10.1, which fixes the issue.

', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-21683', '2024-11-24 08:08:56.643956', 'https://cve.circl.lu/cve/CVE-2024-21683', 'Atlassian Confluence Data Center and Server Remote Code Execution (RCE) Vulnerability (CONFSERVER-95832)', 8.8, 'High', e'This High severity RCE (Remote Code Execution) vulnerability was introduced in version 5.2 of Confluence Data Center and Server.

This RCE (Remote Code Execution) vulnerability, with a CVSS Score of 7.2, allows an authenticated attacker to execute arbitrary code which has high impact to confidentiality, high impact to integrity, high impact to availability, and requires no user interaction. 

Atlassian recommends that Confluence Data Center and Server customers upgrade to latest version. If you are unable to do so, upgrade your instance to one of the specified supported fixed versions. See the release notes https://confluence.atlassian.com/doc/confluence-release-notes-327.html

You can download the latest version of Confluence Data Center and Server from the download center https://www.atlassian.com/software/confluence/download-archives.

This vulnerability was found internally.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-41993', '2024-11-24 08:08:56.643957', 'https://cve.circl.lu/cve/CVE-2023-41993', 'Azul Java Multiple Security Vulnerabilities Security Update April 2024', 8.8, 'High', 'The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14. Processing web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 16.7.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-2004', '2024-11-24 08:08:56.643958', 'https://cve.circl.lu/cve/CVE-2024-2004', 'Debian 12 Security Update for curl (CVE-2024-2004)', 3.5, 'High', 'When a protocol selection parameter option disables all protocols without adding any then the default set of protocols would remain in the allowed set due to an error in the logic for removing protocols. The below command would perform a request to curl.se with a plaintext protocol which has been explicitly disabled.      curl --proto -all,-http http://curl.se  The flaw is only present if the set of selected protocols disables the entire set of available protocols, in itself a command with no practical use and therefore unlikely to be encountered in real situations. The curl security team has thus assessed this to be low severity bug.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-45492', '2024-11-24 08:08:56.643958', 'https://cve.circl.lu/cve/CVE-2024-45492', 'Debian Security Update for expat (DSA 5770-1)', 7.3, 'High', 'An issue was discovered in libexpat before 2.6.3. nextScaffoldPart in xmlparse.c can have an integer overflow for m_groupSize on 32-bit platforms (where UINT_MAX equals SIZE_MAX).', 'Use a language or compiler that performs automatic bounds checking. Carefully review the service''s implementation before making it available to user. For instance you can use manual or automated code review to uncover vulnerabilities such as integer overflow. Use an abstraction library to abstract away risky APIs. Not a complete solution. Always do bound checking before consuming user input data.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-45490', '2024-11-24 08:08:56.643959', 'https://cve.circl.lu/cve/CVE-2024-45490', 'Debian Security Update for expat (DSA 5770-1)', 9.8, 'High', 'An issue was discovered in libexpat before 2.6.3. xmlparse.c does not reject a negative length for XML_ParseBuffer.', 'This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-45491', '2024-11-24 08:08:56.643960', 'https://cve.circl.lu/cve/CVE-2024-45491', 'Debian Security Update for expat (DSA 5770-1)', 7.3, 'High', 'An issue was discovered in libexpat before 2.6.3. dtdCopy in xmlparse.c can have an integer overflow for nDefaultAtts on 32-bit platforms (where UINT_MAX equals SIZE_MAX).', 'Use a language or compiler that performs automatic bounds checking. Carefully review the service''s implementation before making it available to user. For instance you can use manual or automated code review to uncover vulnerabilities such as integer overflow. Use an abstraction library to abstract away risky APIs. Not a complete solution. Always do bound checking before consuming user input data.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4368', '2024-11-24 08:08:56.643961', 'https://cve.circl.lu/cve/CVE-2024-4368', 'Google Chrome Prior to 124.0.6367.118 Multiple Vulnerabilities', 6.3, 'High', 'Use after free in Dawn in Google Chrome prior to 124.0.6367.118 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4331', '2024-11-24 08:08:56.643962', 'https://cve.circl.lu/cve/CVE-2024-4331', 'Google Chrome Prior to 124.0.6367.118 Multiple Vulnerabilities', 7.5, 'High', 'Use after free in Picture In Picture in Google Chrome prior to 124.0.6367.118 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4559', '2024-11-24 08:08:56.643963', 'https://cve.circl.lu/cve/CVE-2024-4559', 'Google Chrome Prior to 124.0.6367.155 Multiple Vulnerabilities', 7.5, 'High', 'Heap buffer overflow in WebAudio in Google Chrome prior to 124.0.6367.155 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4558', '2024-11-24 08:08:56.643963', 'https://cve.circl.lu/cve/CVE-2024-4558', 'Google Chrome Prior to 124.0.6367.155 Multiple Vulnerabilities', 7.5, 'High', 'Use after free in ANGLE in Google Chrome prior to 124.0.6367.155 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4671', '2024-11-24 08:08:56.643964', 'https://cve.circl.lu/cve/CVE-2024-4671', 'Google Chrome Prior to 124.0.6367.201 Multiple Vulnerabilities', 9.6, 'High', 'Use after free in Visuals in Google Chrome prior to 124.0.6367.201 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4761', '2024-11-24 08:08:56.643965', 'https://cve.circl.lu/cve/CVE-2024-4761', 'Google Chrome Prior to 124.0.6367.207 Multiple Vulnerabilities', 7.5, 'High', 'Out of bounds write in V8 in Google Chrome prior to 124.0.6367.207 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5499', '2024-11-24 08:08:56.643966', 'https://cve.circl.lu/cve/CVE-2024-5499', 'Microsoft Edge Based on Chromium Prior to 125.0.2535.85 Multiple Vulnerabilities', 8.8, 'High', 'Out of bounds write in Streams API in Google Chrome prior to 125.0.6422.141 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5498', '2024-11-24 08:08:56.643967', 'https://cve.circl.lu/cve/CVE-2024-5498', 'Microsoft Edge Based on Chromium Prior to 125.0.2535.85 Multiple Vulnerabilities', 5.4, 'High', 'Use after free in Presentation API in Google Chrome prior to 125.0.6422.141 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5497', '2024-11-24 08:08:56.643967', 'https://cve.circl.lu/cve/CVE-2024-5497', 'Microsoft Edge Based on Chromium Prior to 125.0.2535.85 Multiple Vulnerabilities', 7.5, 'High', 'Out of bounds memory access in Browser UI in Google Chrome prior to 125.0.6422.141 allowed a remote attacker who convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5496', '2024-11-24 08:08:56.643968', 'https://cve.circl.lu/cve/CVE-2024-5496', 'Microsoft Edge Based on Chromium Prior to 125.0.2535.85 Multiple Vulnerabilities', 7.5, 'High', 'Use after free in Media Session in Google Chrome prior to 125.0.6422.141 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5495', '2024-11-24 08:08:56.643969', 'https://cve.circl.lu/cve/CVE-2024-5495', 'Microsoft Edge Based on Chromium Prior to 125.0.2535.85 Multiple Vulnerabilities', 7.5, 'High', 'Use after free in Dawn in Google Chrome prior to 125.0.6422.141 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5494', '2024-11-24 08:08:56.643970', 'https://cve.circl.lu/cve/CVE-2024-5494', 'Microsoft Edge Based on Chromium Prior to 125.0.2535.85 Multiple Vulnerabilities', 7.5, 'High', 'Use after free in Dawn in Google Chrome prior to 125.0.6422.141 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5493', '2024-11-24 08:08:56.643970', 'https://cve.circl.lu/cve/CVE-2024-5493', 'Microsoft Edge Based on Chromium Prior to 125.0.2535.85 Multiple Vulnerabilities', 7.5, 'High', 'Heap buffer overflow in WebRTC in Google Chrome prior to 125.0.6422.141 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4950', '2024-11-24 08:08:56.643971', 'https://cve.circl.lu/cve/CVE-2024-4950', 'Google Chrome Prior to 125.0.6422.60 Multiple Vulnerabilities', 5.3, 'High', 'Inappropriate implementation in Downloads in Google Chrome prior to 125.0.6422.60 allowed a remote attacker who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML page. (Chromium security severity: Low)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4949', '2024-11-24 08:08:56.643972', 'https://cve.circl.lu/cve/CVE-2024-4949', 'Google Chrome Prior to 125.0.6422.60 Multiple Vulnerabilities', 9.6, 'High', 'Use after free in V8 in Google Chrome prior to 125.0.6422.60 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4948', '2024-11-24 08:08:56.643973', 'https://cve.circl.lu/cve/CVE-2024-4948', 'Google Chrome Prior to 125.0.6422.60 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Dawn in Google Chrome prior to 125.0.6422.60 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4947', '2024-11-24 08:08:56.643973', 'https://cve.circl.lu/cve/CVE-2024-4947', 'Google Chrome Prior to 125.0.6422.60 Multiple Vulnerabilities', 9.6, 'High', 'Type Confusion in V8 in Google Chrome prior to 125.0.6422.60 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5160', '2024-11-24 08:08:56.643974', 'https://cve.circl.lu/cve/CVE-2024-5160', 'Google Chrome Prior to 125.0.6422.76 Multiple Vulnerabilities', 8.8, 'High', 'Heap buffer overflow in Dawn in Google Chrome prior to 125.0.6422.76 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5159', '2024-11-24 08:08:56.643975', 'https://cve.circl.lu/cve/CVE-2024-5159', 'Google Chrome Prior to 125.0.6422.76 Multiple Vulnerabilities', 8.8, 'High', 'Heap buffer overflow in ANGLE in Google Chrome prior to 125.0.6422.76 allowed a remote attacker to perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5158', '2024-11-24 08:08:56.643976', 'https://cve.circl.lu/cve/CVE-2024-5158', 'Google Chrome Prior to 125.0.6422.76 Multiple Vulnerabilities', 8.8, 'High', 'Type Confusion in V8 in Google Chrome prior to 125.0.6422.76 allowed a remote attacker to potentially perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6100', '2024-11-24 08:08:56.643977', 'https://cve.circl.lu/cve/CVE-2024-6100', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.68 Multiple Vulnerabilities', 8.8, 'High', 'Type Confusion in V8 in Google Chrome prior to 126.0.6478.114 allowed a remote attacker to execute arbitrary code via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6103', '2024-11-24 08:08:56.643977', 'https://cve.circl.lu/cve/CVE-2024-6103', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.68 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Dawn in Google Chrome prior to 126.0.6478.114 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6102', '2024-11-24 08:08:56.643978', 'https://cve.circl.lu/cve/CVE-2024-6102', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.68 Multiple Vulnerabilities', 8.8, 'High', 'Out of bounds memory access in Dawn in Google Chrome prior to 126.0.6478.114 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6101', '2024-11-24 08:08:56.643979', 'https://cve.circl.lu/cve/CVE-2024-6101', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.68 Multiple Vulnerabilities', 8.8, 'High', 'Inappropriate implementation in V8 in Google Chrome prior to 126.0.6478.114 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6293', '2024-11-24 08:08:56.643979', 'https://cve.circl.lu/cve/CVE-2024-6293', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.81 Multiple Vulnerabilities', 7.5, 'High', 'Use after free in Dawn in Google Chrome prior to 126.0.6478.126 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6292', '2024-11-24 08:08:56.643980', 'https://cve.circl.lu/cve/CVE-2024-6292', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.81 Multiple Vulnerabilities', 7.5, 'High', 'Use after free in Dawn in Google Chrome prior to 126.0.6478.126 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6291', '2024-11-24 08:08:56.643981', 'https://cve.circl.lu/cve/CVE-2024-6291', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.81 Multiple Vulnerabilities', 7.5, 'High', 'Use after free in Swiftshader in Google Chrome prior to 126.0.6478.126 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6290', '2024-11-24 08:08:56.643982', 'https://cve.circl.lu/cve/CVE-2024-6290', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.81 Multiple Vulnerabilities', 7.5, 'High', 'Use after free in Dawn in Google Chrome prior to 126.0.6478.126 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6779', '2024-11-24 08:08:56.643982', 'https://cve.circl.lu/cve/CVE-2024-6779', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.113 Multiple Vulnerabilities', 8.8, 'High', 'Out of bounds memory access in V8 in Google Chrome prior to 126.0.6478.182 allowed a remote attacker to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6778', '2024-11-24 08:08:56.643983', 'https://cve.circl.lu/cve/CVE-2024-6778', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.113 Multiple Vulnerabilities', 8.8, 'High', 'Race in DevTools in Google Chrome prior to 126.0.6478.182 allowed an attacker who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via a crafted Chrome Extension. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6777', '2024-11-24 08:08:56.643984', 'https://cve.circl.lu/cve/CVE-2024-6777', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.113 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Navigation in Google Chrome prior to 126.0.6478.182 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6776', '2024-11-24 08:08:56.643985', 'https://cve.circl.lu/cve/CVE-2024-6776', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.113 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Audio in Google Chrome prior to 126.0.6478.182 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6775', '2024-11-24 08:08:56.643985', 'https://cve.circl.lu/cve/CVE-2024-6775', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.113 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Media Stream in Google Chrome prior to 126.0.6478.182 allowed a remote attacker who convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6774', '2024-11-24 08:08:56.643986', 'https://cve.circl.lu/cve/CVE-2024-6774', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.113 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Screen Capture in Google Chrome prior to 126.0.6478.182 allowed a remote attacker who convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6773', '2024-11-24 08:08:56.643987', 'https://cve.circl.lu/cve/CVE-2024-6773', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.113 Multiple Vulnerabilities', 8.8, 'High', 'Inappropriate implementation in V8 in Google Chrome prior to 126.0.6478.182 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6772', '2024-11-24 08:08:56.643988', 'https://cve.circl.lu/cve/CVE-2024-6772', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.113 Multiple Vulnerabilities', 8.8, 'High', 'Inappropriate implementation in V8 in Google Chrome prior to 126.0.6478.182 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5843', '2024-11-24 08:08:56.643988', 'https://cve.circl.lu/cve/CVE-2024-5843', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Inappropriate implementation in Downloads in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to obfuscate security UI via a malicious file. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5842', '2024-11-24 08:08:56.643989', 'https://cve.circl.lu/cve/CVE-2024-5842', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 7.5, 'Medium', 'Use after free in Browser UI in Google Chrome prior to 126.0.6478.54 allowed a remote attacker who convinced a user to engage in specific UI gestures to perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5841', '2024-11-24 08:08:56.643990', 'https://cve.circl.lu/cve/CVE-2024-5841', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7024', '2024-11-24 08:08:56.643991', 'https://cve.circl.lu/cve/CVE-2024-7024', 'Google Chrome Prior to 126.0.6478.54 Multiple Vulnerabilities', 9.3, 'High', 'Inappropriate implementation in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: Low)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5847', '2024-11-24 08:08:56.643991', 'https://cve.circl.lu/cve/CVE-2024-5847', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in PDFium in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially exploit heap corruption via a crafted PDF file. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5846', '2024-11-24 08:08:56.643992', 'https://cve.circl.lu/cve/CVE-2024-5846', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in PDFium in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially exploit heap corruption via a crafted PDF file. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5845', '2024-11-24 08:08:56.643993', 'https://cve.circl.lu/cve/CVE-2024-5845', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in Audio in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially exploit heap corruption via a crafted PDF file. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5839', '2024-11-24 08:08:56.643994', 'https://cve.circl.lu/cve/CVE-2024-5839', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Inappropriate Implementation in Memory Allocator in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5844', '2024-11-24 08:08:56.643994', 'https://cve.circl.lu/cve/CVE-2024-5844', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Heap buffer overflow in Tab Strip in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5838', '2024-11-24 08:08:56.643995', 'https://cve.circl.lu/cve/CVE-2024-5838', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Type Confusion in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5837', '2024-11-24 08:08:56.643996', 'https://cve.circl.lu/cve/CVE-2024-5837', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Type Confusion in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5836', '2024-11-24 08:08:56.643997', 'https://cve.circl.lu/cve/CVE-2024-5836', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Inappropriate Implementation in DevTools in Google Chrome prior to 126.0.6478.54 allowed an attacker who convinced a user to install a malicious extension to execute arbitrary code via a crafted Chrome Extension. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5835', '2024-11-24 08:08:56.643997', 'https://cve.circl.lu/cve/CVE-2024-5835', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 4.2, 'Medium', 'Heap buffer overflow in Tab Groups in Google Chrome prior to 126.0.6478.54 allowed a remote attacker who convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5834', '2024-11-24 08:08:56.643998', 'https://cve.circl.lu/cve/CVE-2024-5834', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 5.6, 'Medium', 'Inappropriate implementation in Dawn in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to execute arbitrary code via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5833', '2024-11-24 08:08:56.643999', 'https://cve.circl.lu/cve/CVE-2024-5833', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Type Confusion in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5832', '2024-11-24 08:08:56.644000', 'https://cve.circl.lu/cve/CVE-2024-5832', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in Dawn in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5831', '2024-11-24 08:08:56.644000', 'https://cve.circl.lu/cve/CVE-2024-5831', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in Dawn in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5830', '2024-11-24 08:08:56.644001', 'https://cve.circl.lu/cve/CVE-2024-5830', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 8.8, 'Medium', 'Type Confusion in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5840', '2024-11-24 08:08:56.644002', 'https://cve.circl.lu/cve/CVE-2024-5840', 'Microsoft Edge Based on Chromium Prior to 126.0.2592.56 Multiple Vulnerabilities', 6.5, 'Medium', 'Policy bypass in CORS in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to bypass discretionary access control via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6991', '2024-11-24 08:08:56.644003', 'https://cve.circl.lu/cve/CVE-2024-6991', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in Dawn in Google Chrome prior to 127.0.6533.72 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6989', '2024-11-24 08:08:56.644003', 'https://cve.circl.lu/cve/CVE-2024-6989', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in Loader in Google Chrome prior to 127.0.6533.72 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6988', '2024-11-24 08:08:56.644004', 'https://cve.circl.lu/cve/CVE-2024-6988', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in Downloads in Google Chrome on iOS prior to 127.0.6533.72 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7005', '2024-11-24 08:08:56.644005', 'https://cve.circl.lu/cve/CVE-2024-7005', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 8.8, 'Medium', 'Insufficient validation of untrusted input in Safe Browsing in Google Chrome prior to 127.0.6533.72 allowed a remote attacker who convinced a user to engage in specific UI gestures to bypass discretionary access control via a malicious file. (Chromium security severity: Low)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7004', '2024-11-24 08:08:56.644006', 'https://cve.circl.lu/cve/CVE-2024-7004', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 4.3, 'Medium', 'Insufficient validation of untrusted input in Safe Browsing in Google Chrome prior to 127.0.6533.72 allowed a remote attacker who convinced a user to engage in specific UI gestures to bypass discretionary access control via a malicious file. (Chromium security severity: Low)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7003', '2024-11-24 08:08:56.644006', 'https://cve.circl.lu/cve/CVE-2024-7003', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 4.3, 'Medium', 'Inappropriate implementation in FedCM in Google Chrome prior to 127.0.6533.72 allowed a remote attacker who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML page. (Chromium security severity: Low)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7000', '2024-11-24 08:08:56.644007', 'https://cve.circl.lu/cve/CVE-2024-7000', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in CSS in Google Chrome prior to 127.0.6533.72 allowed a remote attacker who convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8362', '2024-11-24 08:08:56.644022', 'https://cve.circl.lu/cve/CVE-2024-8362', 'Google Chrome Prior to 128.0.6613.119 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in WebAudio in Google Chrome prior to 128.0.6613.119 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6999', '2024-11-24 08:08:56.644008', 'https://cve.circl.lu/cve/CVE-2024-6999', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 5.5, 'Medium', 'Inappropriate implementation in FedCM in Google Chrome prior to 127.0.6533.72 allowed a remote attacker who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6998', '2024-11-24 08:08:56.644009', 'https://cve.circl.lu/cve/CVE-2024-6998', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in User Education in Google Chrome prior to 127.0.6533.72 allowed a remote attacker who convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6997', '2024-11-24 08:08:56.644009', 'https://cve.circl.lu/cve/CVE-2024-6997', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 8.8, 'Medium', 'Use after free in Tabs in Google Chrome prior to 127.0.6533.72 allowed a remote attacker who convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6995', '2024-11-24 08:08:56.644010', 'https://cve.circl.lu/cve/CVE-2024-6995', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 8.8, 'Medium', 'Inappropriate implementation in Fullscreen in Google Chrome on Android prior to 127.0.6533.72 allowed a remote attacker who convinced a user to engage in specific UI gestures to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6994', '2024-11-24 08:08:56.644011', 'https://cve.circl.lu/cve/CVE-2024-6994', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.74 Multiple Vulnerabilities', 8.8, 'Medium', 'Heap buffer overflow in Layout in Google Chrome prior to 127.0.6533.72 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6990', '2024-11-24 08:08:56.644012', 'https://cve.circl.lu/cve/CVE-2024-6990', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.86/Extended Stable Prior to 126.0.2592.132 Multiple Vulnerabilities', 8.8, 'High', 'Uninitialized Use in Dawn in Google Chrome on Android prior to 127.0.6533.88 allowed a remote attacker to potentially perform out of bounds memory access via a crafted HTML page. (Chromium security severity: Critical)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7256', '2024-11-24 08:08:56.644012', 'https://cve.circl.lu/cve/CVE-2024-7256', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.86/Extended Stable Prior to 126.0.2592.132 Multiple Vulnerabilities', 8.8, 'High', 'Insufficient data validation in Dawn in Google Chrome on Android prior to 127.0.6533.88 allowed a remote attacker to execute arbitrary code via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7255', '2024-11-24 08:08:56.644013', 'https://cve.circl.lu/cve/CVE-2024-7255', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.86/Extended Stable Prior to 126.0.2592.132 Multiple Vulnerabilities', 8.8, 'High', 'Out of bounds read in WebTransport in Google Chrome prior to 127.0.6533.88 allowed a remote attacker to potentially perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7532', '2024-11-24 08:08:56.644014', 'https://cve.circl.lu/cve/CVE-2024-7532', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.98 Multiple Vulnerabilities', 8.8, 'High', 'Out of bounds memory access in ANGLE in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7533', '2024-11-24 08:08:56.644015', 'https://cve.circl.lu/cve/CVE-2024-7533', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.98 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Sharing in Google Chrome on iOS prior to 127.0.6533.99 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7536', '2024-11-24 08:08:56.644016', 'https://cve.circl.lu/cve/CVE-2024-7536', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.98 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in WebAudio in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7535', '2024-11-24 08:08:56.644016', 'https://cve.circl.lu/cve/CVE-2024-7535', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.98 Multiple Vulnerabilities', 8.8, 'High', 'Inappropriate implementation in V8 in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7534', '2024-11-24 08:08:56.644017', 'https://cve.circl.lu/cve/CVE-2024-7534', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.98 Multiple Vulnerabilities', 8.8, 'High', 'Heap buffer overflow in Layout in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7550', '2024-11-24 08:08:56.644018', 'https://cve.circl.lu/cve/CVE-2024-7550', 'Microsoft Edge Based on Chromium Prior to 127.0.2651.98 Multiple Vulnerabilities', 8.8, 'High', 'Type Confusion in V8 in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8198', '2024-11-24 08:08:56.644019', 'https://cve.circl.lu/cve/CVE-2024-8198', 'Google Chrome Prior to 128.0.6613.113 Multiple Vulnerabilities', 7.5, 'High', 'Heap buffer overflow in Skia in Google Chrome prior to 128.0.6613.113 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8194', '2024-11-24 08:08:56.644019', 'https://cve.circl.lu/cve/CVE-2024-8194', 'Google Chrome Prior to 128.0.6613.113 Multiple Vulnerabilities', 7.5, 'High', 'Type Confusion in V8 in Google Chrome prior to 128.0.6613.113 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8193', '2024-11-24 08:08:56.644020', 'https://cve.circl.lu/cve/CVE-2024-8193', 'Google Chrome Prior to 128.0.6613.113 Multiple Vulnerabilities', 8.8, 'High', 'Heap buffer overflow in Skia in Google Chrome prior to 128.0.6613.113 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7969', '2024-11-24 08:08:56.644021', 'https://cve.circl.lu/cve/CVE-2024-7969', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 8.8, 'High', 'Type Confusion in V8 in Google Chrome prior to 128.0.6613.113 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7970', '2024-11-24 08:08:56.644022', 'https://cve.circl.lu/cve/CVE-2024-7970', 'Google Chrome Prior to 128.0.6613.119 Multiple Vulnerabilities', 8.8, 'High', 'Out of bounds write in V8 in Google Chrome prior to 128.0.6613.119 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7973', '2024-11-24 08:08:56.644023', 'https://cve.circl.lu/cve/CVE-2024-7973', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 8.8, 'High', 'Heap buffer overflow in PDFium in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to perform an out of bounds memory read via a crafted PDF file. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7972', '2024-11-24 08:08:56.644024', 'https://cve.circl.lu/cve/CVE-2024-7972', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 8.1, 'High', 'Inappropriate implementation in V8 in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to potentially perform out of bounds memory access via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7971', '2024-11-24 08:08:56.644025', 'https://cve.circl.lu/cve/CVE-2024-7971', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 8.8, 'High', 'Type confusion in V8 in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7968', '2024-11-24 08:08:56.644025', 'https://cve.circl.lu/cve/CVE-2024-7968', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Autofill in Google Chrome prior to 128.0.6613.84 allowed a remote attacker who had convinced the user to engage in specific UI interactions to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7980', '2024-11-24 08:08:56.644026', 'https://cve.circl.lu/cve/CVE-2024-7980', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 7.3, 'High', 'Insufficient data validation in Installer in Google Chrome on Windows prior to 128.0.6613.84 allowed a local attacker to perform privilege escalation via a crafted symbolic link. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7979', '2024-11-24 08:08:56.644027', 'https://cve.circl.lu/cve/CVE-2024-7979', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 7, 'High', 'Insufficient data validation in Installer in Google Chrome on Windows prior to 128.0.6613.84 allowed a local attacker to perform privilege escalation via a crafted symbolic link. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7978', '2024-11-24 08:08:56.644028', 'https://cve.circl.lu/cve/CVE-2024-7978', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 4.3, 'High', 'Insufficient policy enforcement in Data Transfer in Google Chrome prior to 128.0.6613.84 allowed a remote attacker who convinced a user to engage in specific UI gestures to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7977', '2024-11-24 08:08:56.644028', 'https://cve.circl.lu/cve/CVE-2024-7977', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 7.8, 'High', 'Insufficient data validation in Installer in Google Chrome on Windows prior to 128.0.6613.84 allowed a local attacker to perform privilege escalation via a malicious file. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7974', '2024-11-24 08:08:56.644029', 'https://cve.circl.lu/cve/CVE-2024-7974', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 6.3, 'High', 'Insufficient data validation in V8 API in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to potentially exploit heap corruption via a crafted Chrome Extension. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7967', '2024-11-24 08:08:56.644030', 'https://cve.circl.lu/cve/CVE-2024-7967', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 8.8, 'High', 'Heap buffer overflow in Fonts in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7966', '2024-11-24 08:08:56.644031', 'https://cve.circl.lu/cve/CVE-2024-7966', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 8.8, 'High', 'Out of bounds memory access in Skia in Google Chrome prior to 128.0.6613.84 allowed a remote attacker who had compromised the renderer process to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)', 'Use a language or compiler that performs automatic bounds checking. Use an abstraction library to abstract away risky APIs. Not a complete solution. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Do not trust input data from user. Validate all user input.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7965', '2024-11-24 08:08:56.644031', 'https://cve.circl.lu/cve/CVE-2024-7965', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 8.8, 'High', 'Inappropriate implementation in V8 in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7964', '2024-11-24 08:08:56.644032', 'https://cve.circl.lu/cve/CVE-2024-7964', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.42 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Passwords in Google Chrome on Android prior to 128.0.6613.84 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8905', '2024-11-24 08:08:56.644033', 'https://cve.circl.lu/cve/CVE-2024-8905', 'Microsoft Edge Based on Chromium Prior to 129.0.2792.52/Extended Stable 128.0.2739.90 Multiple Vulnerabilities', 8.8, 'High', 'Inappropriate implementation in V8 in Google Chrome prior to 129.0.6668.58 allowed a remote attacker to potentially exploit stack corruption via a crafted HTML page. (Chromium security severity: Medium)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8904', '2024-11-24 08:08:56.644034', 'https://cve.circl.lu/cve/CVE-2024-8904', 'Microsoft Edge Based on Chromium Prior to 129.0.2792.52/Extended Stable 128.0.2739.90 Multiple Vulnerabilities', 8.8, 'High', 'Type Confusion in V8 in Google Chrome prior to 129.0.6668.58 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9123', '2024-11-24 08:08:56.644034', 'https://cve.circl.lu/cve/CVE-2024-9123', 'Microsoft Edge Based on Chromium Prior to 129.0.2792.65/Extended Stable 128.0.2739.97 Multiple Vulnerabilities', 7.1, 'High', 'Integer overflow in Skia in Google Chrome prior to 129.0.6668.70 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9122', '2024-11-24 08:08:56.644035', 'https://cve.circl.lu/cve/CVE-2024-9122', 'Microsoft Edge Based on Chromium Prior to 129.0.2792.65/Extended Stable 128.0.2739.97 Multiple Vulnerabilities', 8.8, 'High', 'Type Confusion in V8 in Google Chrome prior to 129.0.6668.70 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9121', '2024-11-24 08:08:56.644036', 'https://cve.circl.lu/cve/CVE-2024-9121', 'Microsoft Edge Based on Chromium Prior to 129.0.2792.65/Extended Stable 128.0.2739.97 Multiple Vulnerabilities', 8.8, 'High', 'Inappropriate implementation in V8 in Google Chrome prior to 129.0.6668.70 allowed a remote attacker to potentially perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9120', '2024-11-24 08:08:56.644036', 'https://cve.circl.lu/cve/CVE-2024-9120', 'Microsoft Edge Based on Chromium Prior to 129.0.2792.65/Extended Stable 128.0.2739.97 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Dawn in Google Chrome on Windows prior to 129.0.6668.70 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5535', '2024-11-24 08:08:56.644037', 'https://cve.circl.lu/cve/CVE-2024-5535', 'IBM Advanced Interactive eXecutive (AIX) Open Secure Sockets Layer (OpenSSL) Multiple Vulnerabilities (openssl_advisory42)', 9.1, 'High', e'Issue summary: Calling the OpenSSL API function SSL_select_next_proto with an
empty supported client protocols buffer may cause a crash or memory contents to
be sent to the peer.

Impact summary: A buffer overread can have a range of potential consequences
such as unexpected application beahviour or a crash. In particular this issue
could result in up to 255 bytes of arbitrary private data from memory being sent
to the peer leading to a loss of confidentiality. However, only applications
that directly call the SSL_select_next_proto function with a 0 length list of
supported client protocols are affected by this issue. This would normally never
be a valid scenario and is typically not under attacker control but may occur by
accident in the case of a configuration or programming error in the calling
application.

The OpenSSL API function SSL_select_next_proto is typically used by TLS
applications that support ALPN (Application Layer Protocol Negotiation) or NPN
(Next Protocol Negotiation). NPN is older, was never standardised and
is deprecated in favour of ALPN. We believe that ALPN is significantly more
widely deployed than NPN. The SSL_select_next_proto function accepts a list of
protocols from the server and a list of protocols from the client and returns
the first protocol that appears in the server list that also appears in the
client list. In the case of no overlap between the two lists it returns the
first item in the client list. In either case it will signal whether an overlap
between the two lists was found. In the case where SSL_select_next_proto is
called with a zero length client list it fails to notice this condition and
returns the memory immediately following the client list pointer (and reports
that there was no overlap in the lists).

This function is typically called from a server side application callback for
ALPN or a client side application callback for NPN. In the case of ALPN the list
of protocols supplied by the client is guaranteed by libssl to never be zero in
length. The list of server protocols comes from the application and should never
normally be expected to be of zero length. In this case if the
SSL_select_next_proto function has been called as expected (with the list
supplied by the client passed in the client/client_len parameters), then the
application will not be vulnerable to this issue. If the application has
accidentally been configured with a zero length server list, and has
accidentally passed that zero length server list in the client/client_len
parameters, and has additionally failed to correctly handle a "no overlap"
response (which would normally result in a handshake failure in ALPN) then it
will be vulnerable to this problem.

In the case of NPN, the protocol permits the client to opportunistically select
a protocol when there is no overlap. OpenSSL returns the first client protocol
in the no overlap case in support of this. The list of client protocols comes
from the application and should never normally be expected to be of zero length.
However if the SSL_select_next_proto function is accidentally called with a
client_len of 0 then an invalid memory pointer will be returned instead. If the
application uses this output as the opportunistic protocol then the loss of
confidentiality will occur.

This issue has been assessed as Low severity because applications are most
likely to be vulnerable if they are using NPN instead of ALPN - but NPN is not
widely used. It also requires an application configuration or programming error.
Finally, this issue would not typically be under attacker control making active
exploitation unlikely.

The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.

Due to the low severity of this issue we are not issuing new releases of
OpenSSL at this time. The fix will be included in the next releases when they
become available.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-45853', '2024-11-24 08:08:56.644038', 'https://cve.circl.lu/cve/CVE-2023-45853', 'IBM DB2 Denial of Service (DoS) Vulnerability (7156844)', 8.8, 'High', 'MiniZip in zlib through 1.3 has an integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_64 via a long filename, comment, or extra field. NOTE: MiniZip is not a supported part of the zlib product. NOTE: pyminizip through 0.2.6 is also vulnerable because it bundles an affected zlib version, and exposes the applicable MiniZip code through its compress API.', 'Use a language or compiler that performs automatic bounds checking. Carefully review the service''s implementation before making it available to user. For instance you can use manual or automated code review to uncover vulnerabilities such as integer overflow. Use an abstraction library to abstract away risky APIs. Not a complete solution. Always do bound checking before consuming user input data.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8639', '2024-11-24 08:08:56.644039', 'https://cve.circl.lu/cve/CVE-2024-8639', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.79 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Autofill in Google Chrome on Android prior to 128.0.6613.137 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8638', '2024-11-24 08:08:56.644039', 'https://cve.circl.lu/cve/CVE-2024-8638', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.79 Multiple Vulnerabilities', 8.8, 'High', 'Type Confusion in V8 in Google Chrome prior to 128.0.6613.137 allowed a remote attacker to potentially exploit object corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8637', '2024-11-24 08:08:56.644040', 'https://cve.circl.lu/cve/CVE-2024-8637', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.79 Multiple Vulnerabilities', 8.8, 'High', 'Use after free in Media Router in Google Chrome on Android prior to 128.0.6613.137 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8636', '2024-11-24 08:08:56.644041', 'https://cve.circl.lu/cve/CVE-2024-8636', 'Microsoft Edge Based on Chromium Prior to 128.0.2739.79 Multiple Vulnerabilities', 8.8, 'High', 'Heap buffer overflow in Skia in Google Chrome prior to 128.0.6613.137 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-24023', '2024-11-24 08:56:10.512945', 'https://cve.circl.lu/cve/CVE-2023-24023', 'Microsoft Windows Security Update for November 2023', 6.4, 'High', 'Bluetooth BR/EDR devices with Secure Simple Pairing and Secure Connections pairing in Bluetooth Core Specification 4.2 through 5.4 allow certain man-in-the-middle attacks that force a short key length, and might lead to discovery of the encryption key and live injection, aka BLUFFS.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-1546', '2024-11-24 08:56:10.512957', 'https://cve.circl.lu/cve/CVE-2024-1546', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-06)', 7.5, 'High', 'When storing and re-accessing data on a networking channel, the length of buffers may have been confused, resulting in an out-of-bounds memory read. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-1548', '2024-11-24 08:56:10.512958', 'https://cve.circl.lu/cve/CVE-2024-1548', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-06)', 4.3, 'High', 'A website could have obscured the fullscreen notification by using a dropdown select input element. This could have led to user confusion and possible spoofing attacks. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-1551', '2024-11-24 08:56:10.512958', 'https://cve.circl.lu/cve/CVE-2024-1551', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-06)', 6.1, 'High', 'Set-Cookie response headers were being incorrectly honored in multipart HTTP responses. If an attacker could control the Content-Type response header, as well as control part of the response body, they could inject Set-Cookie response headers that would have been honored by the browser. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-2616', '2024-11-24 08:56:10.512959', 'https://cve.circl.lu/cve/CVE-2024-2616', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-13)', 2.7, 'High', 'To harden ICU against exploitation, the behavior for out-of-memory conditions was changed to crash instead of attempt to continue. This vulnerability affects Firefox ESR < 115.9 and Thunderbird < 115.9.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-5388', '2024-11-24 08:56:10.512960', 'https://cve.circl.lu/cve/CVE-2023-5388', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-13)', 6.5, 'High', 'NSS was susceptible to a timing side-channel attack when performing RSA decryption. This attack could potentially allow an attacker to recover the private data. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and Thunderbird < 115.9.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-2610', '2024-11-24 08:56:10.512960', 'https://cve.circl.lu/cve/CVE-2024-2610', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-13)', 6.1, 'High', 'Using a markup injection an attacker could have stolen nonce values. This could have been used to bypass strict content security policies. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and Thunderbird < 115.9.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-2611', '2024-11-24 08:56:10.512964', 'https://cve.circl.lu/cve/CVE-2024-2611', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-13)', 5.5, 'High', 'A missing delay on when pointer lock was used could have allowed a malicious page to trick a user into granting permissions. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and Thunderbird < 115.9.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-3302', '2024-11-24 08:56:10.512965', 'https://cve.circl.lu/cve/CVE-2024-3302', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-19)', 3.7, 'High', 'There was no limit to the number of HTTP/2 CONTINUATION frames that would be processed. A server could abuse this to create an Out of Memory condition in the browser. This vulnerability affects Firefox < 125, Firefox ESR < 115.10, and Thunderbird < 115.10.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-3859', '2024-11-24 08:56:10.512965', 'https://cve.circl.lu/cve/CVE-2024-3859', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-19)', 5.9, 'High', 'On 32-bit versions there were integer-overflows that led to an out-of-bounds-read that potentially could be triggered by a malformed OpenType font. This vulnerability affects Firefox < 125, Firefox ESR < 115.10, and Thunderbird < 115.10.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-3861', '2024-11-24 08:56:10.512966', 'https://cve.circl.lu/cve/CVE-2024-3861', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-19)', 4, 'High', 'If an AlignedBuffer were assigned to itself, the subsequent self-move could result in an incorrect reference count and later use-after-free. This vulnerability affects Firefox < 125, Firefox ESR < 115.10, and Thunderbird < 115.10.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-3857', '2024-11-24 08:56:10.512966', 'https://cve.circl.lu/cve/CVE-2024-3857', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-19)', 7.8, 'High', 'The JIT created incorrect code for arguments in certain cases. This led to potential use-after-free crashes during garbage collection. This vulnerability affects Firefox < 125, Firefox ESR < 115.10, and Thunderbird < 115.10.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-3854', '2024-11-24 08:56:10.512967', 'https://cve.circl.lu/cve/CVE-2024-3854', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-19)', 8.8, 'High', 'In some code patterns the JIT incorrectly optimized switch statements and generated code with out-of-bounds-reads. This vulnerability affects Firefox < 125, Firefox ESR < 115.10, and Thunderbird < 115.10.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-3864', '2024-11-24 08:56:10.512968', 'https://cve.circl.lu/cve/CVE-2024-3864', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-19)', 8.1, 'High', 'Memory safety bug present in Firefox 124, Firefox ESR 115.9, and Thunderbird 115.9. This bug showed evidence of memory corruption and we presume that with enough effort this could have been exploited to run arbitrary code. This vulnerability affects Firefox < 125, Firefox ESR < 115.10, and Thunderbird < 115.10.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-3852', '2024-11-24 08:56:10.512968', 'https://cve.circl.lu/cve/CVE-2024-3852', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-19)', 7.5, 'High', 'GetBoundName could return the wrong version of an object when JIT optimizations were applied. This vulnerability affects Firefox < 125, Firefox ESR < 115.10, and Thunderbird < 115.10.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4767', '2024-11-24 08:56:10.512969', 'https://cve.circl.lu/cve/CVE-2024-4767', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-22)', 4.3, 'High', 'If the `browser.privatebrowsing.autostart` preference is enabled, IndexedDB files were not properly deleted when the window was closed. This preference is disabled by default in Firefox. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird < 115.11.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4769', '2024-11-24 08:56:10.512969', 'https://cve.circl.lu/cve/CVE-2024-4769', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-22)', 5.9, 'High', 'When importing resources using Web Workers, error messages would distinguish the difference between `application/javascript` responses and non-script responses.  This could have been abused to learn information cross-origin. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird < 115.11.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4768', '2024-11-24 08:56:10.512970', 'https://cve.circl.lu/cve/CVE-2024-4768', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-22)', 6.1, 'High', 'A bug in popup notifications'' interaction with WebAuthn made it easier for an attacker to trick a user into granting permissions. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird < 115.11.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-4770', '2024-11-24 08:56:10.512971', 'https://cve.circl.lu/cve/CVE-2024-4770', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-22)', 8.8, 'High', 'When saving a page to PDF, certain font styles could have led to a potential use-after-free crash. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird < 115.11.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5688', '2024-11-24 08:56:10.512971', 'https://cve.circl.lu/cve/CVE-2024-5688', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-26)', 8.1, 'High', 'If a garbage collection was triggered at the right time, a use-after-free could have occurred during object transplant. This vulnerability affects Firefox < 127, Firefox ESR < 115.12, and Thunderbird < 115.12.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5693', '2024-11-24 08:56:10.512972', 'https://cve.circl.lu/cve/CVE-2024-5693', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-26)', 6.1, 'High', 'Offscreen Canvas did not properly track cross-origin tainting, which could be used to access image data from another site in violation of same-origin policy. This vulnerability affects Firefox < 127, Firefox ESR < 115.12, and Thunderbird < 115.12.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5696', '2024-11-24 08:56:10.512972', 'https://cve.circl.lu/cve/CVE-2024-5696', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-26)', 8.6, 'High', 'By manipulating the text in an `&lt;input&gt;` tag, an attacker could have caused corrupt memory leading to a potentially exploitable crash. This vulnerability affects Firefox < 127, Firefox ESR < 115.12, and Thunderbird < 115.12.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5700', '2024-11-24 08:56:10.512973', 'https://cve.circl.lu/cve/CVE-2024-5700', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-26)', 7, 'High', 'Memory safety bugs present in Firefox 126, Firefox ESR 115.11, and Thunderbird 115.11. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 127, Firefox ESR < 115.12, and Thunderbird < 115.12.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5692', '2024-11-24 08:56:10.512973', 'https://cve.circl.lu/cve/CVE-2024-5692', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-26)', 6.5, 'High', 'On Windows 10, when using the ''Save As'' functionality, an attacker could have tricked the browser into saving the file with a disallowed extension such as `.url` by including an invalid character in the extension. *Note:* This issue only affected Windows operating systems. Other operating systems are unaffected. This vulnerability affects Firefox < 127, Firefox ESR < 115.12, and Thunderbird < 115.12.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5702', '2024-11-24 08:56:10.512974', 'https://cve.circl.lu/cve/CVE-2024-5702', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-26)', 7.5, 'High', 'Memory corruption in the networking stack could have led to a potentially exploitable crash. This vulnerability affects Firefox < 125, Firefox ESR < 115.12, and Thunderbird < 115.12.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6604', '2024-11-24 08:56:10.512975', 'https://cve.circl.lu/cve/CVE-2024-6604', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-30)', 7.5, 'High', 'Memory safety bugs present in Firefox 127, Firefox ESR 115.12, and Thunderbird 115.12. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 128, Firefox ESR < 115.13, Thunderbird < 115.13, and Thunderbird < 128.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6602', '2024-11-24 08:56:10.512976', 'https://cve.circl.lu/cve/CVE-2024-6602', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-30)', 9.8, 'High', 'A mismatch between allocator and deallocator could have lead to memory corruption. This vulnerability affects Firefox < 128, Firefox ESR < 115.13, Thunderbird < 115.13, and Thunderbird < 128.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6603', '2024-11-24 08:56:10.512976', 'https://cve.circl.lu/cve/CVE-2024-6603', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-30)', 7.4, 'High', 'In an out-of-memory scenario an allocation could fail but free would have been called on the pointer afterwards leading to memory corruption. This vulnerability affects Firefox < 128, Firefox ESR < 115.13, Thunderbird < 115.13, and Thunderbird < 128.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6601', '2024-11-24 08:56:10.512977', 'https://cve.circl.lu/cve/CVE-2024-6601', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-30)', 4.7, 'High', 'A race condition could lead to a cross-origin container obtaining permissions of the top-level origin. This vulnerability affects Firefox < 128, Firefox ESR < 115.13, Thunderbird < 115.13, and Thunderbird < 128.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7525', '2024-11-24 08:56:10.512977', 'https://cve.circl.lu/cve/CVE-2024-7525', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-34)', 9.1, 'High', 'It was possible for a web extension with minimal permissions to create a `StreamFilter` which could be used to read and modify the response body of requests on any site. This vulnerability affects Firefox < 129, Firefox ESR < 115.14, Firefox ESR < 128.1, Thunderbird < 128.1, and Thunderbird < 115.14.', 'Design: Use input validation before writing to web log Design: Validate all log data before it is output');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9403', '2024-11-24 08:56:10.512994', 'https://cve.circl.lu/cve/CVE-2024-9403', 'Mozilla Firefox Multiple Vulnerabilities (MFSA2024-46)', 7.3, 'High', 'Memory safety bugs present in Firefox 130. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 131 and Thunderbird < 131.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7531', '2024-11-24 08:56:10.512978', 'https://cve.circl.lu/cve/CVE-2024-7531', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-34)', 6.3, 'High', 'Calling `PK11_Encrypt()` in NSS using CKM_CHACHA20 and the same buffer for input and output can result in plaintext on an Intel Sandy Bridge processor. In Firefox this only affects the QUIC header protection feature when the connection is using the ChaCha20-Poly1305 cipher suite. The most likely outcome is connection failure, but if the connection persists despite the high packet loss it could be possible for a network observer to identify packets as coming from the same source despite a network path change. This vulnerability affects Firefox < 129, Firefox ESR < 115.14, and Firefox ESR < 128.1.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7521', '2024-11-24 08:56:10.512979', 'https://cve.circl.lu/cve/CVE-2024-7521', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-34)', 9.8, 'High', 'Incomplete WebAssembly exception handing could have led to a use-after-free. This vulnerability affects Firefox < 129, Firefox ESR < 115.14, Firefox ESR < 128.1, Thunderbird < 128.1, and Thunderbird < 115.14.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7526', '2024-11-24 08:56:10.512979', 'https://cve.circl.lu/cve/CVE-2024-7526', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-34)', 7.5, 'High', 'ANGLE failed to initialize parameters which lead to reading from uninitialized memory. This could be leveraged to leak sensitive data from memory. This vulnerability affects Firefox < 129, Firefox ESR < 115.14, Firefox ESR < 128.1, Thunderbird < 128.1, and Thunderbird < 115.14.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7529', '2024-11-24 08:56:10.512980', 'https://cve.circl.lu/cve/CVE-2024-7529', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-34)', 8.1, 'High', 'The date picker could partially obscure security prompts. This could be used by a malicious site to trick a user into granting permissions. This vulnerability affects Firefox < 129, Firefox ESR < 115.14, Firefox ESR < 128.1, Thunderbird < 128.1, and Thunderbird < 115.14.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7522', '2024-11-24 08:56:10.512984', 'https://cve.circl.lu/cve/CVE-2024-7522', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-34)', 9.1, 'High', 'Editor code failed to check an attribute value. This could have led to an out-of-bounds read. This vulnerability affects Firefox < 129, Firefox ESR < 115.14, Firefox ESR < 128.1, Thunderbird < 128.1, and Thunderbird < 115.14.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7527', '2024-11-24 08:56:10.512985', 'https://cve.circl.lu/cve/CVE-2024-7527', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-34)', 8.8, 'High', 'Unexpected marking work at the start of sweeping could have led to a use-after-free. This vulnerability affects Firefox < 129, Firefox ESR < 115.14, Firefox ESR < 128.1, Thunderbird < 128.1, and Thunderbird < 115.14.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7519', '2024-11-24 08:56:10.512985', 'https://cve.circl.lu/cve/CVE-2024-7519', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-34)', 8.8, 'High', 'Insufficient checks when processing graphics shared memory could have led to memory corruption. This could be leveraged by an attacker to perform a sandbox escape. This vulnerability affects Firefox < 129, Firefox ESR < 115.14, Firefox ESR < 128.1, Thunderbird < 128.1, and Thunderbird < 115.14.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8381', '2024-11-24 08:56:10.512986', 'https://cve.circl.lu/cve/CVE-2024-8381', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-41)', 9.8, 'High', 'A potentially exploitable type confusion could be triggered when looking up a property name on an object being used as the `with` environment. This vulnerability affects Firefox < 130, Firefox ESR < 128.2, Firefox ESR < 115.15, Thunderbird < 128.2, and Thunderbird < 115.15.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8383', '2024-11-24 08:56:10.512987', 'https://cve.circl.lu/cve/CVE-2024-8383', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-41)', 7.5, 'High', 'Firefox normally asks for confirmation before asking the operating system to find an application to handle a scheme that the browser does not support. It did not ask before doing so for the Usenet-related schemes news: and snews:. Since most operating systems don''t have a trusted newsreader installed by default, an unscrupulous program that the user downloaded could register itself as a handler. The website that served the application download could then launch that application at will. This vulnerability affects Firefox < 130, Firefox ESR < 128.2, and Firefox ESR < 115.15.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8382', '2024-11-24 08:56:10.512987', 'https://cve.circl.lu/cve/CVE-2024-8382', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-41)', 8.8, 'High', 'Internal browser event interfaces were exposed to web content when privileged EventHandler listener callbacks ran for those events. Web content that tried to use those interfaces would not be able to use them with elevated privileges, but their presence would indicate certain browser features had been used, such as when a user opened the Dev Tools console. This vulnerability affects Firefox < 130, Firefox ESR < 128.2, Firefox ESR < 115.15, Thunderbird < 128.2, and Thunderbird < 115.15.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-8384', '2024-11-24 08:56:10.512988', 'https://cve.circl.lu/cve/CVE-2024-8384', 'Mozilla Firefox ESR Multiple Vulnerabilities (MFSA2024-41)', 9.8, 'High', 'The JavaScript garbage collector could mis-color cross-compartment objects if OOM conditions were detected at the right point between two passes. This could have led to memory corruption. This vulnerability affects Firefox < 130, Firefox ESR < 128.2, Firefox ESR < 115.15, Thunderbird < 128.2, and Thunderbird < 115.15.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9400', '2024-11-24 08:56:10.512988', 'https://cve.circl.lu/cve/CVE-2024-9400', 'Mozilla Firefox Multiple Vulnerabilities (MFSA2024-46)', 8.8, 'High', 'A potential memory corruption vulnerability could be triggered if an attacker had the ability to trigger an OOM at a specific moment during JIT compilation. This vulnerability affects Firefox < 131, Firefox ESR < 128.3, Thunderbird < 128.3, and Thunderbird < 131.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9401', '2024-11-24 08:56:10.512989', 'https://cve.circl.lu/cve/CVE-2024-9401', 'Mozilla Firefox Multiple Vulnerabilities (MFSA2024-46)', 9.8, 'High', 'Memory safety bugs present in Firefox 130, Firefox ESR 115.15, Firefox ESR 128.2, and Thunderbird 128.2. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 131, Firefox ESR < 128.3, Firefox ESR < 115.16, Thunderbird < 128.3, and Thunderbird < 131.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9402', '2024-11-24 08:56:10.512990', 'https://cve.circl.lu/cve/CVE-2024-9402', 'Mozilla Firefox Multiple Vulnerabilities (MFSA2024-46)', 9.8, 'High', 'Memory safety bugs present in Firefox 130, Firefox ESR 128.2, and Thunderbird 128.2. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 131, Firefox ESR < 128.3, Thunderbird < 128.3, and Thunderbird < 131.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9396', '2024-11-24 08:56:10.512993', 'https://cve.circl.lu/cve/CVE-2024-9396', 'Mozilla Firefox Multiple Vulnerabilities (MFSA2024-46)', 8.8, 'High', 'It is currently unknown if this issue is exploitable but a condition may arise where the structured clone of certain objects could lead to memory corruption. This vulnerability affects Firefox < 131, Firefox ESR < 128.3, Thunderbird < 128.3, and Thunderbird < 131.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9392', '2024-11-24 08:56:10.512994', 'https://cve.circl.lu/cve/CVE-2024-9392', 'Mozilla Firefox Multiple Vulnerabilities (MFSA2024-46)', 9.8, 'High', 'A compromised content process could have allowed for the arbitrary loading of cross-origin pages. This vulnerability affects Firefox < 131, Firefox ESR < 128.3, Firefox ESR < 115.16, Thunderbird < 128.3, and Thunderbird < 131.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9391', '2024-11-24 08:56:10.512995', 'https://cve.circl.lu/cve/CVE-2024-9391', 'Mozilla Firefox Multiple Vulnerabilities (MFSA2024-46)', 6.5, 'High', e'A user who enables full-screen mode on a specially crafted web page could potentially be prevented from exiting full screen mode.  This may allow spoofing of other sites as the address bar is no longer visible.
*This bug only affects Firefox Focus for Android. Other versions of Firefox are unaffected.* This vulnerability affects Firefox < 131.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-9395', '2024-11-24 08:56:10.512995', 'https://cve.circl.lu/cve/CVE-2024-9395', 'Mozilla Firefox Multiple Vulnerabilities (MFSA2024-46)', 5.3, 'High', e'A specially crafted filename containing a large number of spaces could obscure the file\'s extension when displayed in the download dialog.
*This bug only affects Firefox for Android. Other versions of Firefox are unaffected.* This vulnerability affects Firefox < 131.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-24783', '2024-11-24 08:56:10.512996', 'https://cve.circl.lu/cve/CVE-2024-24783', 'Oracle Enterprise Linux Security Update for container-tools:ol8 (ELSA-2024-6969)', 5.9, 'High', 'Verifying a certificate chain which contains a certificate with an unknown public key algorithm will cause Certificate.Verify to panic. This affects all crypto/tls clients, and servers that set Config.ClientAuth to VerifyClientCertIfGiven or RequireAndVerifyClientCert. The default behavior is for TLS servers to not verify client certificates.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-45290', '2024-11-24 08:56:10.512997', 'https://cve.circl.lu/cve/CVE-2023-45290', 'Oracle Enterprise Linux Security Update for container-tools:ol8 (ELSA-2024-6969)', 6.5, 'High', 'When parsing a multipart form (either explicitly with Request.ParseMultipartForm or implicitly with Request.FormValue, Request.PostFormValue, or Request.FormFile), limits on the total size of the parsed form were not applied to the memory consumed while reading a single form line. This permits a maliciously crafted input containing very long lines to cause allocation of arbitrarily large amounts of memory, potentially leading to memory exhaustion. With fix, the ParseMultipartForm function now correctly limits the maximum size of form lines.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-24791', '2024-11-24 08:56:10.512998', 'https://cve.circl.lu/cve/CVE-2024-24791', 'Oracle Enterprise Linux Security Update for container-tools:ol8 (ELSA-2024-6969)', 7.5, 'High', 'The net/http HTTP/1.1 client mishandled the case where a server responds to a request with an "Expect: 100-continue" header with a non-informational (200 or higher) status. This mishandling could leave a client connection in an invalid state, where the next request sent on the connection will fail. An attacker sending a request to a net/http/httputil.ReverseProxy proxy can exploit this mishandling to cause a denial of service by sending "Expect: 100-continue" requests which elicit a non-informational response from the backend. Each such request leaves the proxy with an invalid connection, and causes one subsequent request using that connection to fail.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-24788', '2024-11-24 08:56:10.512998', 'https://cve.circl.lu/cve/CVE-2024-24788', 'Oracle Enterprise Linux Security Update for container-tools:ol8 (ELSA-2024-6969)', 5.9, 'High', 'A malformed DNS message in response to a query can cause the Lookup functions to get stuck in an infinite loop.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-39331', '2024-11-24 08:56:10.512999', 'https://cve.circl.lu/cve/CVE-2024-39331', 'Oracle Enterprise Linux Security Update for emacs (ELSA-2024-6987)', 9.8, 'High', 'In Emacs before 29.4, org-link-expand-abbrev in lisp/ol.el expands a %(...) link abbrev even when it specifies an unsafe function, such as shell-command-to-string. This affects Org Mode before 9.7.5.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-30203', '2024-11-24 08:56:10.513000', 'https://cve.circl.lu/cve/CVE-2024-30203', 'Oracle Enterprise Linux Security Update for emacs (ELSA-2024-6987)', 5.5, 'High', 'In Emacs before 29.3, Gnus treats inline MIME contents as trusted.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-6923', '2024-11-24 08:56:10.513002', 'https://cve.circl.lu/cve/CVE-2024-6923', 'Oracle Enterprise Linux Security Update for python3 (ELSA-2024-6975)', 5.5, 'High', e'There is a MEDIUM severity vulnerability affecting CPython.

The 
email module didn’t properly quote newlines for email headers when 
serializing an email message allowing for header injection when an email
 is serialized.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-36894', '2024-11-24 08:56:10.513003', 'https://cve.circl.lu/cve/CVE-2024-36894', 'Oracle Enterprise Linux Security Update for unbreakable enterprise kernel (ELSA-2024-12618)', 5.6, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

usb: gadget: f_fs: Fix race between aio_cancel() and AIO request complete

FFS based applications can utilize the aio_cancel() callback to dequeue
pending USB requests submitted to the UDC.  There is a scenario where the
FFS application issues an AIO cancel call, while the UDC is handling a
soft disconnect.  For a DWC3 based implementation, the callstack looks
like the following:

    DWC3 Gadget                               FFS Application
dwc3_gadget_soft_disconnect()              ...
  --> dwc3_stop_active_transfers()
    --> dwc3_gadget_giveback(-ESHUTDOWN)
      --> ffs_epfile_async_io_complete()   ffs_aio_cancel()
        --> usb_ep_free_request()            --> usb_ep_dequeue()

There is currently no locking implemented between the AIO completion
handler and AIO cancel, so the issue occurs if the completion routine is
running in parallel to an AIO cancel call coming from the FFS application.
As the completion call frees the USB request (io_data->req) the FFS
application is also referencing it for the usb_ep_dequeue() call.  This can
lead to accessing a stale/hanging pointer.

commit b566d38857fc ("usb: gadget: f_fs: use io_data->status consistently")
relocated the usb_ep_free_request() into ffs_epfile_async_io_complete().
However, in order to properly implement locking to mitigate this issue, the
spinlock can\'t be added to ffs_epfile_async_io_complete(), as
usb_ep_dequeue() (if successfully dequeuing a USB request) will call the
function driver\'s completion handler in the same context.  Hence, leading
into a deadlock.

Fix this issue by moving the usb_ep_free_request() back to
ffs_user_copy_worker(), and ensuring that it explicitly sets io_data->req
to NULL after freeing it within the ffs->eps_lock.  This resolves the race
condition above, as the ffs_aio_cancel() routine will not continue
attempting to dequeue a request that has already been freed, or the
ffs_user_copy_work() not freeing the USB request until the AIO cancel is
done referencing it.

This fix depends on
  commit b566d38857fc ("usb: gadget: f_fs: use io_data->status
  consistently")', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-36032', '2024-11-24 08:56:10.513003', 'https://cve.circl.lu/cve/CVE-2024-36032', 'Oracle Enterprise Linux Security Update for unbreakable enterprise kernel (ELSA-2024-12618)', 2.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

Bluetooth: qca: fix info leak when fetching fw build id

Add the missing sanity checks and move the 255-byte build-id buffer off
the stack to avoid leaking stack data through debugfs in case the
build-info reply is malformed.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26779', '2024-11-24 09:01:55.235352', 'https://cve.circl.lu/cve/CVE-2024-26779', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6831-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

wifi: mac80211: fix race condition on enabling fast-xmit

fast-xmit must only be enabled after the sta has been uploaded to the driver,
otherwise it could end up passing the not-yet-uploaded sta via drv_tx calls
to the driver, leading to potential crashes because of uninitialized drv_priv
data.
Add a missing sta->uploaded check and re-check fast xmit after inserting a sta.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26744', '2024-11-24 09:01:55.235353', 'https://cve.circl.lu/cve/CVE-2024-26744', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

RDMA/srpt: Support specifying the srpt_service_guid parameter

Make loading ib_srpt with this parameter set work. The current behavior is
that setting that parameter while loading the ib_srpt kernel module
triggers the following kernel crash:

BUG: kernel NULL pointer dereference, address: 0000000000000000
Call Trace:
 <TASK>
 parse_one+0x18c/0x1d0
 parse_args+0xe1/0x230
 load_module+0x8de/0xa60
 init_module_from_file+0x8b/0xd0
 idempotent_init_module+0x181/0x240
 __x64_sys_finit_module+0x5a/0xb0
 do_syscall_64+0x5f/0xe0
 entry_SYSCALL_64_after_hwframe+0x6e/0x76', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38588', '2024-11-24 08:56:10.513004', 'https://cve.circl.lu/cve/CVE-2024-38588', 'Oracle Enterprise Linux Security Update for unbreakable enterprise kernel (ELSA-2024-12618)', 7.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

ftrace: Fix possible use-after-free issue in ftrace_location()

KASAN reports a bug:

  BUG: KASAN: use-after-free in ftrace_location+0x90/0x120
  Read of size 8 at addr ffff888141d40010 by task insmod/424
  CPU: 8 PID: 424 Comm: insmod Tainted: G        W          6.9.0-rc2+
  [...]
  Call Trace:
   <TASK>
   dump_stack_lvl+0x68/0xa0
   print_report+0xcf/0x610
   kasan_report+0xb5/0xe0
   ftrace_location+0x90/0x120
   register_kprobe+0x14b/0xa40
   kprobe_init+0x2d/0xff0 [kprobe_example]
   do_one_initcall+0x8f/0x2d0
   do_init_module+0x13a/0x3c0
   load_module+0x3082/0x33d0
   init_module_from_file+0xd2/0x130
   __x64_sys_finit_module+0x306/0x440
   do_syscall_64+0x68/0x140
   entry_SYSCALL_64_after_hwframe+0x71/0x79

The root cause is that, in lookup_rec(), ftrace record of some address
is being searched in ftrace pages of some module, but those ftrace pages
at the same time is being freed in ftrace_release_mod() as the
corresponding module is being deleted:

           CPU1                       |      CPU2
  register_kprobes() {                | delete_module() {
    check_kprobe_address_safe() {     |
      arch_check_ftrace_location() {  |
        ftrace_location() {           |
          lookup_rec() // USE!        |   ftrace_release_mod() // Free!

To fix this issue:
  1. Hold rcu lock as accessing ftrace pages in ftrace_location_range();
  2. Use ftrace_location_range() instead of lookup_rec() in
     ftrace_location();
  3. Call synchronize_rcu() before freeing any ftrace pages both in
     ftrace_process_locs()/ftrace_release_mod()/ftrace_free_mem().', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-36367', '2024-11-24 09:01:55.235329', 'https://cve.circl.lu/cve/CVE-2021-36367', 'Putty Multiple Security Vulnerabilities', 8.1, 'Medium', 'PuTTY through 0.75 proceeds with establishing an SSH session even if it has never sent a substantive authentication response. This makes it easier for an attacker-controlled SSH server to present a later spoofed authentication prompt (that the attacker can use to capture credential data, and use that data for purposes that are undesired by the client user).', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-24786', '2024-11-24 09:01:55.235333', 'https://cve.circl.lu/cve/CVE-2024-24786', 'Red Hat Update for container-tools (RHSA-2024:4246)', 7.5, 'Medium', 'The protojson.Unmarshal function can enter an infinite loop when unmarshaling certain forms of invalid JSON. This condition can occur when unmarshaling into a message which contains a google.protobuf.Any value, or when the UnmarshalOptions.DiscardUnknown option is set.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-27561', '2024-11-24 09:01:55.235334', 'https://cve.circl.lu/cve/CVE-2023-27561', 'Red Hat Update for container-tools:rhel8 (RHSA-2023:6939)', 7, 'Medium', 'runc through 1.1.4 has Incorrect Access Control leading to Escalation of Privileges, related to libcontainer/rootfs_linux.go. To exploit this, an attacker must be able to spawn two containers with custom volume-mount configurations, and be able to run custom images. NOTE: this issue exists because of a CVE-2019-19921 regression.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-24789', '2024-11-24 09:01:55.235335', 'https://cve.circl.lu/cve/CVE-2024-24789', 'Red Hat Update for container-tools:rhel8 (RHSA-2024:5258)', 5.3, 'High', 'The archive/zip package''s handling of certain types of invalid zip files differs from the behavior of most zip implementations. This misalignment could be exploited to create an zip file with contents that vary depending on the implementation reading the file. The archive/zip package now rejects files containing these errors.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-2398', '2024-11-24 09:01:55.235341', 'https://cve.circl.lu/cve/CVE-2024-2398', 'Red Hat Update for curl (RHSA-2024:5654)', 8.6, 'Medium', 'When an application tells libcurl it wants to allow HTTP/2 server push, and the amount of received headers for the push surpasses the maximum allowed limit (1000), libcurl aborts the server push. When aborting, libcurl inadvertently does not free all the previously allocated headers and instead leaks the memory.  Further, this error condition fails silently and is therefore not easily detected by an application.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-34397', '2024-11-24 09:01:55.235345', 'https://cve.circl.lu/cve/CVE-2024-34397', 'Ubuntu Security Notification for GLib Vulnerability (USN-6768-1)', 5.2, 'High', 'An issue was discovered in GNOME GLib before 2.78.5, and 2.79.x and 2.80.x before 2.80.1. When a GDBus-based client subscribes to signals from a trusted system service such as NetworkManager on a shared computer, other users of the same computer can send spoofed D-Bus signals that the GDBus-based client will wrongly interpret as having been sent by the trusted system service. This could lead to the GDBus-based client behaving incorrectly, with an application-dependent impact.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-2961', '2024-11-24 09:01:55.235346', 'https://cve.circl.lu/cve/CVE-2024-2961', 'Red Hat Update for glibc (RHSA-2024:3269)', 7.3, 'High', e'The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.
', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-33602', '2024-11-24 09:01:55.235347', 'https://cve.circl.lu/cve/CVE-2024-33602', 'Ubuntu Security Notification for GNU C Library Vulnerabilities (USN-6804-1)', 7.4, 'High', e'nscd: netgroup cache assumes NSS callback uses in-buffer strings

The Name Service Cache Daemon\'s (nscd) netgroup cache can corrupt memory
when the NSS callback does not store all strings in the provided buffer.
The flaw was introduced in glibc 2.15 when the cache was added to nscd.

This vulnerability is only present in the nscd binary.

', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-33601', '2024-11-24 09:01:55.235347', 'https://cve.circl.lu/cve/CVE-2024-33601', 'Ubuntu Security Notification for GNU C Library Vulnerabilities (USN-6804-1)', 7.5, 'High', e'nscd: netgroup cache may terminate daemon on memory allocation failure

The Name Service Cache Daemon\'s (nscd) netgroup cache uses xmalloc or
xrealloc and these functions may terminate the process due to a memory
allocation failure resulting in a denial of service to the clients.  The
flaw was introduced in glibc 2.15 when the cache was added to nscd.

This vulnerability is only present in the nscd binary.

', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-38709', '2024-11-24 09:01:55.235351', 'https://cve.circl.lu/cve/CVE-2023-38709', 'Red Hat Update for httpd:2.4/httpd (RHSA-2024:4197)', 7.3, 'Medium', e'Faulty input validation in the core of Apache allows malicious or exploitable backend/content generators to split HTTP responses.

This issue affects Apache HTTP Server: through 2.4.58.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27316', '2024-11-24 09:01:55.235351', 'https://cve.circl.lu/cve/CVE-2024-27316', 'Red Hat Update for httpd:2.4/mod_http2 (RHSA-2024:1786)', 7.5, 'High', 'HTTP/2 incoming headers exceeding the limit are temporarily buffered in nghttp2 in order to generate an informative HTTP 413 response. If a client does not stop sending headers, this leads to memory exhaustion.', 'This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26804', '2024-11-24 09:01:55.235352', 'https://cve.circl.lu/cve/CVE-2024-26804', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6831-1)', 5.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

net: ip_tunnel: prevent perpetual headroom growth

syzkaller triggered following kasan splat:
BUG: KASAN: use-after-free in __skb_flow_dissect+0x19d1/0x7a50 net/core/flow_dissector.c:1170
Read of size 1 at addr ffff88812fb4000e by task syz-executor183/5191
[..]
 kasan_report+0xda/0x110 mm/kasan/report.c:588
 __skb_flow_dissect+0x19d1/0x7a50 net/core/flow_dissector.c:1170
 skb_flow_dissect_flow_keys include/linux/skbuff.h:1514 [inline]
 ___skb_get_hash net/core/flow_dissector.c:1791 [inline]
 __skb_get_hash+0xc7/0x540 net/core/flow_dissector.c:1856
 skb_get_hash include/linux/skbuff.h:1556 [inline]
 ip_tunnel_xmit+0x1855/0x33c0 net/ipv4/ip_tunnel.c:748
 ipip_tunnel_xmit+0x3cc/0x4e0 net/ipv4/ipip.c:308
 __netdev_start_xmit include/linux/netdevice.h:4940 [inline]
 netdev_start_xmit include/linux/netdevice.h:4954 [inline]
 xmit_one net/core/dev.c:3548 [inline]
 dev_hard_start_xmit+0x13d/0x6d0 net/core/dev.c:3564
 __dev_queue_xmit+0x7c1/0x3d60 net/core/dev.c:4349
 dev_queue_xmit include/linux/netdevice.h:3134 [inline]
 neigh_connected_output+0x42c/0x5d0 net/core/neighbour.c:1592
 ...
 ip_finish_output2+0x833/0x2550 net/ipv4/ip_output.c:235
 ip_finish_output+0x31/0x310 net/ipv4/ip_output.c:323
 ..
 iptunnel_xmit+0x5b4/0x9b0 net/ipv4/ip_tunnel_core.c:82
 ip_tunnel_xmit+0x1dbc/0x33c0 net/ipv4/ip_tunnel.c:831
 ipgre_xmit+0x4a1/0x980 net/ipv4/ip_gre.c:665
 __netdev_start_xmit include/linux/netdevice.h:4940 [inline]
 netdev_start_xmit include/linux/netdevice.h:4954 [inline]
 xmit_one net/core/dev.c:3548 [inline]
 dev_hard_start_xmit+0x13d/0x6d0 net/core/dev.c:3564
 ...

The splat occurs because skb->data points past skb->head allocated area.
This is because neigh layer does:
  __skb_pull(skb, skb_network_offset(skb));

... but skb_network_offset() returns a negative offset and __skb_pull()
arg is unsigned.  IOW, we skb->data gets "adjusted" by a huge value.

The negative value is returned because skb->head and skb->data distance is
more than 64k and skb->network_header (u16) has wrapped around.

The bug is in the ip_tunnel infrastructure, which can cause
dev->needed_headroom to increment ad infinitum.

The syzkaller reproducer consists of packets getting routed via a gre
tunnel, and route of gre encapsulated packets pointing at another (ipip)
tunnel.  The ipip encapsulation finds gre0 as next output device.

This results in the following pattern:

1). First packet is to be sent out via gre0.
Route lookup found an output device, ipip0.

2).
ip_tunnel_xmit for gre0 bumps gre0->needed_headroom based on the future
output device, rt.dev->needed_headroom (ipip0).

3).
ip output / start_xmit moves skb on to ipip0. which runs the same
code path again (xmit recursion).

4).
Routing step for the post-gre0-encap packet finds gre0 as output device
to use for ipip0 encapsulated packet.

tunl0->needed_headroom is then incremented based on the (already bumped)
gre0 device headroom.

This repeats for every future packet:

gre0->needed_headroom gets inflated because previous packets\' ipip0 step
incremented rt->dev (gre0) headroom, and ipip0 incremented because gre0
needed_headroom was increased.

For each subsequent packet, gre/ipip0->needed_headroom grows until
post-expand-head reallocations result in a skb->head/data distance of
more than 64k.

Once that happens, skb->network_header (u16) wraps around when
pskb_expand_head tries to make sure that skb_network_offset() is unchanged
after the headroom expansion/reallocation.

After this skb_network_offset(skb) returns a different (and negative)
result post headroom expansion.

The next trip to neigh layer (or anything else that would __skb_pull the
network header) makes skb->data point to a memory location outside
skb->head area.

v2: Cap the needed_headroom update to an arbitarily chosen upperlimit to
prevent perpetual increase instead of dropping the headroom increment
completely.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47400', '2024-11-24 09:01:55.235368', 'https://cve.circl.lu/cve/CVE-2021-47400', 'Red Hat Update for kernel (RHSA-2024:4349)', 4, 'Medium', e'In the Linux kernel, the following vulnerability has been resolved:

net: hns3: do not allow call hns3_nic_net_open repeatedly

hns3_nic_net_open() is not allowed to called repeatly, but there
is no checking for this. When doing device reset and setup tc
concurrently, there is a small oppotunity to call hns3_nic_net_open
repeatedly, and cause kernel bug by calling napi_enable twice.

The calltrace information is like below:
[ 3078.222780] ------------[ cut here ]------------
[ 3078.230255] kernel BUG at net/core/dev.c:6991!
[ 3078.236224] Internal error: Oops - BUG: 0 [#1] PREEMPT SMP
[ 3078.243431] Modules linked in: hns3 hclgevf hclge hnae3 vfio_iommu_type1 vfio_pci vfio_virqfd vfio pv680_mii(O)
[ 3078.258880] CPU: 0 PID: 295 Comm: kworker/u8:5 Tainted: G           O      5.14.0-rc4+ #1
[ 3078.269102] Hardware name:  , BIOS KpxxxFPGA 1P B600 V181 08/12/2021
[ 3078.276801] Workqueue: hclge hclge_service_task [hclge]
[ 3078.288774] pstate: 60400009 (nZCv daif +PAN -UAO -TCO BTYPE=--)
[ 3078.296168] pc : napi_enable+0x80/0x84
tc qdisc sho[w  3d0e7v8 .e3t0h218 79] lr : hns3_nic_net_open+0x138/0x510 [hns3]

[ 3078.314771] sp : ffff8000108abb20
[ 3078.319099] x29: ffff8000108abb20 x28: 0000000000000000 x27: ffff0820a8490300
[ 3078.329121] x26: 0000000000000001 x25: ffff08209cfc6200 x24: 0000000000000000
[ 3078.339044] x23: ffff0820a8490300 x22: ffff08209cd76000 x21: ffff0820abfe3880
[ 3078.349018] x20: 0000000000000000 x19: ffff08209cd76900 x18: 0000000000000000
[ 3078.358620] x17: 0000000000000000 x16: ffffc816e1727a50 x15: 0000ffff8f4ff930
[ 3078.368895] x14: 0000000000000000 x13: 0000000000000000 x12: 0000259e9dbeb6b4
[ 3078.377987] x11: 0096a8f7e764eb40 x10: 634615ad28d3eab5 x9 : ffffc816ad8885b8
[ 3078.387091] x8 : ffff08209cfc6fb8 x7 : ffff0820ac0da058 x6 : ffff0820a8490344
[ 3078.396356] x5 : 0000000000000140 x4 : 0000000000000003 x3 : ffff08209cd76938
[ 3078.405365] x2 : 0000000000000000 x1 : 0000000000000010 x0 : ffff0820abfe38a0
[ 3078.414657] Call trace:
[ 3078.418517]  napi_enable+0x80/0x84
[ 3078.424626]  hns3_reset_notify_up_enet+0x78/0xd0 [hns3]
[ 3078.433469]  hns3_reset_notify+0x64/0x80 [hns3]
[ 3078.441430]  hclge_notify_client+0x68/0xb0 [hclge]
[ 3078.450511]  hclge_reset_rebuild+0x524/0x884 [hclge]
[ 3078.458879]  hclge_reset_service_task+0x3c4/0x680 [hclge]
[ 3078.467470]  hclge_service_task+0xb0/0xb54 [hclge]
[ 3078.475675]  process_one_work+0x1dc/0x48c
[ 3078.481888]  worker_thread+0x15c/0x464
[ 3078.487104]  kthread+0x160/0x170
[ 3078.492479]  ret_from_fork+0x10/0x18
[ 3078.498785] Code: c8027c81 35ffffa2 d50323bf d65f03c0 (d4210000)
[ 3078.506889] ---[ end trace 8ebe0340a1b0fb44 ]---

Once hns3_nic_net_open() is excute success, the flag
HNS3_NIC_STATE_DOWN will be cleared. So add checking for this
flag, directly return when HNS3_NIC_STATE_DOWN is no set.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52607', '2024-11-24 09:01:55.235354', 'https://cve.circl.lu/cve/CVE-2023-52607', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6767-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

powerpc/mm: Fix null-pointer dereference in pgtable_cache_add

kasprintf() returns a pointer to dynamically allocated memory
which can be NULL upon failure. Ensure the allocation was successful
by checking the pointer validity.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2022-48669', '2024-11-24 09:01:55.235355', 'https://cve.circl.lu/cve/CVE-2022-48669', 'Red Hat Update for kernel (RHSA-2024:3618)', 5.5, 'Medium', e'In the Linux kernel, the following vulnerability has been resolved:

powerpc/pseries: Fix potential memleak in papr_get_attr()

`buf` is allocated in papr_get_attr(), and krealloc() of `buf`
could fail. We need to free the original `buf` in the case of failure.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2022-48627', '2024-11-24 09:01:55.235355', 'https://cve.circl.lu/cve/CVE-2022-48627', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

vt: fix memory overlapping when deleting chars in the buffer

A memory overlapping copy occurs when deleting a long line. This memory
overlapping copy can cause data corruption when scr_memcpyw is optimized
to memcpy because memcpy does not ensure its behavior if the destination
buffer overlaps with the source buffer. The line buffer is not always
broken, because the memcpy utilizes the hardware acceleration, whose
result is not deterministic.

Fix this problem by using replacing the scr_memcpyw with scr_memmovew.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47185', '2024-11-24 09:01:55.235356', 'https://cve.circl.lu/cve/CVE-2021-47185', 'Red Hat Update for kernel (RHSA-2024:3618)', 4.4, 'Medium', e'In the Linux kernel, the following vulnerability has been resolved:

tty: tty_buffer: Fix the softlockup issue in flush_to_ldisc

When running ltp testcase(ltp/testcases/kernel/pty/pty04.c) with arm64, there is a soft lockup,
which look like this one:

  Workqueue: events_unbound flush_to_ldisc
  Call trace:
   dump_backtrace+0x0/0x1ec
   show_stack+0x24/0x30
   dump_stack+0xd0/0x128
   panic+0x15c/0x374
   watchdog_timer_fn+0x2b8/0x304
   __run_hrtimer+0x88/0x2c0
   __hrtimer_run_queues+0xa4/0x120
   hrtimer_interrupt+0xfc/0x270
   arch_timer_handler_phys+0x40/0x50
   handle_percpu_devid_irq+0x94/0x220
   __handle_domain_irq+0x88/0xf0
   gic_handle_irq+0x84/0xfc
   el1_irq+0xc8/0x180
   slip_unesc+0x80/0x214 [slip]
   tty_ldisc_receive_buf+0x64/0x80
   tty_port_default_receive_buf+0x50/0x90
   flush_to_ldisc+0xbc/0x110
   process_one_work+0x1d4/0x4b0
   worker_thread+0x180/0x430
   kthread+0x11c/0x120

In the testcase pty04, The first process call the write syscall to send
data to the pty master. At the same time, the workqueue will do the
flush_to_ldisc to pop data in a loop until there is no more data left.
When the sender and workqueue running in different core, the sender sends
data fastly in full time which will result in workqueue doing work in loop
for a long time and occuring softlockup in flush_to_ldisc with kernel
configured without preempt. So I add need_resched check and cond_resched
in the flush_to_ldisc loop to avoid it.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47153', '2024-11-24 09:01:55.235357', 'https://cve.circl.lu/cve/CVE-2021-47153', 'Red Hat Update for kernel (RHSA-2024:3618)', 6, 'Medium', e'In the Linux kernel, the following vulnerability has been resolved:

i2c: i801: Don\'t generate an interrupt on bus reset

Now that the i2c-i801 driver supports interrupts, setting the KILL bit
in a attempt to recover from a timed out transaction triggers an
interrupt. Unfortunately, the interrupt handler (i801_isr) is not
prepared for this situation and will try to process the interrupt as
if it was signaling the end of a successful transaction. In the case
of a block transaction, this can result in an out-of-range memory
access.

This condition was reproduced several times by syzbot:
https://syzkaller.appspot.com/bug?extid=ed71512d469895b5b34e
https://syzkaller.appspot.com/bug?extid=8c8dedc0ba9e03f6c79e
https://syzkaller.appspot.com/bug?extid=c8ff0b6d6c73d81b610e
https://syzkaller.appspot.com/bug?extid=33f6c360821c399d69eb
https://syzkaller.appspot.com/bug?extid=be15dc0b1933f04b043a
https://syzkaller.appspot.com/bug?extid=b4d3fd1dfd53e90afd79

So disable interrupts while trying to reset the bus. Interrupts will
be enabled again for the following transaction.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27052', '2024-11-24 09:01:55.235357', 'https://cve.circl.lu/cve/CVE-2024-27052', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 7.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

wifi: rtl8xxxu: add cancel_work_sync() for c2hcmd_work

The workqueue might still be running, when the driver is stopped. To
avoid a use-after-free, call cancel_work_sync() in rtl8xxxu_stop().', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26901', '2024-11-24 09:01:55.235358', 'https://cve.circl.lu/cve/CVE-2024-26901', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak

syzbot identified a kernel information leak vulnerability in
do_sys_name_to_handle() and issued the following report [1].

[1]
"BUG: KMSAN: kernel-infoleak in instrument_copy_to_user include/linux/instrumented.h:114 [inline]
BUG: KMSAN: kernel-infoleak in _copy_to_user+0xbc/0x100 lib/usercopy.c:40
 instrument_copy_to_user include/linux/instrumented.h:114 [inline]
 _copy_to_user+0xbc/0x100 lib/usercopy.c:40
 copy_to_user include/linux/uaccess.h:191 [inline]
 do_sys_name_to_handle fs/fhandle.c:73 [inline]
 __do_sys_name_to_handle_at fs/fhandle.c:112 [inline]
 __se_sys_name_to_handle_at+0x949/0xb10 fs/fhandle.c:94
 __x64_sys_name_to_handle_at+0xe4/0x140 fs/fhandle.c:94
 ...

Uninit was created at:
 slab_post_alloc_hook+0x129/0xa70 mm/slab.h:768
 slab_alloc_node mm/slub.c:3478 [inline]
 __kmem_cache_alloc_node+0x5c9/0x970 mm/slub.c:3517
 __do_kmalloc_node mm/slab_common.c:1006 [inline]
 __kmalloc+0x121/0x3c0 mm/slab_common.c:1020
 kmalloc include/linux/slab.h:604 [inline]
 do_sys_name_to_handle fs/fhandle.c:39 [inline]
 __do_sys_name_to_handle_at fs/fhandle.c:112 [inline]
 __se_sys_name_to_handle_at+0x441/0xb10 fs/fhandle.c:94
 __x64_sys_name_to_handle_at+0xe4/0x140 fs/fhandle.c:94
 ...

Bytes 18-19 of 20 are uninitialized
Memory access of size 20 starts at ffff888128a46380
Data copied to user address 0000000020000240"

Per Chuck Lever\'s suggestion, use kzalloc() instead of kmalloc() to
solve the problem.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26735', '2024-11-24 09:01:55.235359', 'https://cve.circl.lu/cve/CVE-2024-26735', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6831-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

ipv6: sr: fix possible use-after-free and null-ptr-deref

The pernet operations structure for the subsystem must be registered
before registering the generic netlink family.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38593', '2024-11-24 09:01:55.235369', 'https://cve.circl.lu/cve/CVE-2024-38593', 'Red Hat Update for kernel (RHSA-2024:4583)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

net: micrel: Fix receiving the timestamp in the frame for lan8841

The blamed commit started to use the ptp workqueue to get the second
part of the timestamp. And when the port was set down, then this
workqueue is stopped. But if the config option NETWORK_PHY_TIMESTAMPING
is not enabled, then the ptp_clock is not initialized so then it would
crash when it would try to access the delayed work.
So then basically by setting up and then down the port, it would crash.
The fix consists in checking if the ptp_clock is initialized and only
then cancel the delayed work.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-36007', '2024-11-24 09:01:55.235359', 'https://cve.circl.lu/cve/CVE-2024-36007', 'Red Hat Update for kernel (RHSA-2024:4211)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

mlxsw: spectrum_acl_tcam: Fix warning during rehash

As previously explained, the rehash delayed work migrates filters from
one region to another. This is done by iterating over all chunks (all
the filters with the same priority) in the region and in each chunk
iterating over all the filters.

When the work runs out of credits it stores the current chunk and entry
as markers in the per-work context so that it would know where to resume
the migration from the next time the work is scheduled.

Upon error, the chunk marker is reset to NULL, but without resetting the
entry markers despite being relative to it. This can result in migration
being resumed from an entry that does not belong to the chunk being
migrated. In turn, this will eventually lead to a chunk being iterated
over as if it is an entry. Because of how the two structures happen to
be defined, this does not lead to KASAN splats, but to warnings such as
[1].

Fix by creating a helper that resets all the markers and call it from
all the places the currently only reset the chunk marker. For good
measures also call it when starting a completely new rehash. Add a
warning to avoid future cases.

[1]
WARNING: CPU: 7 PID: 1076 at drivers/net/ethernet/mellanox/mlxsw/core_acl_flex_keys.c:407 mlxsw_afk_encode+0x242/0x2f0
Modules linked in:
CPU: 7 PID: 1076 Comm: kworker/7:24 Tainted: G        W          6.9.0-rc3-custom-00880-g29e61d91b77b #29
Hardware name: Mellanox Technologies Ltd. MSN3700/VMOD0005, BIOS 5.11 01/06/2019
Workqueue: mlxsw_core mlxsw_sp_acl_tcam_vregion_rehash_work
RIP: 0010:mlxsw_afk_encode+0x242/0x2f0
[...]
Call Trace:
 <TASK>
 mlxsw_sp_acl_atcam_entry_add+0xd9/0x3c0
 mlxsw_sp_acl_tcam_entry_create+0x5e/0xa0
 mlxsw_sp_acl_tcam_vchunk_migrate_all+0x109/0x290
 mlxsw_sp_acl_tcam_vregion_rehash_work+0x6c/0x470
 process_one_work+0x151/0x370
 worker_thread+0x2cb/0x3e0
 kthread+0xd0/0x100
 ret_from_fork+0x34/0x50
 </TASK>', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35888', '2024-11-24 09:01:55.235360', 'https://cve.circl.lu/cve/CVE-2024-35888', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

erspan: make sure erspan_base_hdr is present in skb->head

syzbot reported a problem in ip6erspan_rcv() [1]

Issue is that ip6erspan_rcv() (and erspan_rcv()) no longer make
sure erspan_base_hdr is present in skb linear part (skb->head)
before getting @ver field from it.

Add the missing pskb_may_pull() calls.

v2: Reload iph pointer in erspan_rcv() after pskb_may_pull()
    because skb->head might have changed.

[1]

 BUG: KMSAN: uninit-value in pskb_may_pull_reason include/linux/skbuff.h:2742 [inline]
 BUG: KMSAN: uninit-value in pskb_may_pull include/linux/skbuff.h:2756 [inline]
 BUG: KMSAN: uninit-value in ip6erspan_rcv net/ipv6/ip6_gre.c:541 [inline]
 BUG: KMSAN: uninit-value in gre_rcv+0x11f8/0x1930 net/ipv6/ip6_gre.c:610
  pskb_may_pull_reason include/linux/skbuff.h:2742 [inline]
  pskb_may_pull include/linux/skbuff.h:2756 [inline]
  ip6erspan_rcv net/ipv6/ip6_gre.c:541 [inline]
  gre_rcv+0x11f8/0x1930 net/ipv6/ip6_gre.c:610
  ip6_protocol_deliver_rcu+0x1d4c/0x2ca0 net/ipv6/ip6_input.c:438
  ip6_input_finish net/ipv6/ip6_input.c:483 [inline]
  NF_HOOK include/linux/netfilter.h:314 [inline]
  ip6_input+0x15d/0x430 net/ipv6/ip6_input.c:492
  ip6_mc_input+0xa7e/0xc80 net/ipv6/ip6_input.c:586
  dst_input include/net/dst.h:460 [inline]
  ip6_rcv_finish+0x955/0x970 net/ipv6/ip6_input.c:79
  NF_HOOK include/linux/netfilter.h:314 [inline]
  ipv6_rcv+0xde/0x390 net/ipv6/ip6_input.c:310
  __netif_receive_skb_one_core net/core/dev.c:5538 [inline]
  __netif_receive_skb+0x1da/0xa00 net/core/dev.c:5652
  netif_receive_skb_internal net/core/dev.c:5738 [inline]
  netif_receive_skb+0x58/0x660 net/core/dev.c:5798
  tun_rx_batched+0x3ee/0x980 drivers/net/tun.c:1549
  tun_get_user+0x5566/0x69e0 drivers/net/tun.c:2002
  tun_chr_write_iter+0x3af/0x5d0 drivers/net/tun.c:2048
  call_write_iter include/linux/fs.h:2108 [inline]
  new_sync_write fs/read_write.c:497 [inline]
  vfs_write+0xb63/0x1520 fs/read_write.c:590
  ksys_write+0x20f/0x4c0 fs/read_write.c:643
  __do_sys_write fs/read_write.c:655 [inline]
  __se_sys_write fs/read_write.c:652 [inline]
  __x64_sys_write+0x93/0xe0 fs/read_write.c:652
 do_syscall_64+0xd5/0x1f0
 entry_SYSCALL_64_after_hwframe+0x6d/0x75

Uninit was created at:
  slab_post_alloc_hook mm/slub.c:3804 [inline]
  slab_alloc_node mm/slub.c:3845 [inline]
  kmem_cache_alloc_node+0x613/0xc50 mm/slub.c:3888
  kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:577
  __alloc_skb+0x35b/0x7a0 net/core/skbuff.c:668
  alloc_skb include/linux/skbuff.h:1318 [inline]
  alloc_skb_with_frags+0xc8/0xbf0 net/core/skbuff.c:6504
  sock_alloc_send_pskb+0xa81/0xbf0 net/core/sock.c:2795
  tun_alloc_skb drivers/net/tun.c:1525 [inline]
  tun_get_user+0x209a/0x69e0 drivers/net/tun.c:1846
  tun_chr_write_iter+0x3af/0x5d0 drivers/net/tun.c:2048
  call_write_iter include/linux/fs.h:2108 [inline]
  new_sync_write fs/read_write.c:497 [inline]
  vfs_write+0xb63/0x1520 fs/read_write.c:590
  ksys_write+0x20f/0x4c0 fs/read_write.c:643
  __do_sys_write fs/read_write.c:655 [inline]
  __se_sys_write fs/read_write.c:652 [inline]
  __x64_sys_write+0x93/0xe0 fs/read_write.c:652
 do_syscall_64+0xd5/0x1f0
 entry_SYSCALL_64_after_hwframe+0x6d/0x75

CPU: 1 PID: 5045 Comm: syz-executor114 Not tainted 6.9.0-rc1-syzkaller-00021-g962490525cff #0', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35958', '2024-11-24 09:01:55.235360', 'https://cve.circl.lu/cve/CVE-2024-35958', 'Red Hat Update for kernel (RHSA-2024:4583)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

net: ena: Fix incorrect descriptor free behavior

ENA has two types of TX queues:
- queues which only process TX packets arriving from the network stack
- queues which only process TX packets forwarded to it by XDP_REDIRECT
  or XDP_TX instructions

The ena_free_tx_bufs() cycles through all descriptors in a TX queue
and unmaps + frees every descriptor that hasn\'t been acknowledged yet
by the device (uncompleted TX transactions).
The function assumes that the processed TX queue is necessarily from
the first category listed above and ends up using napi_consume_skb()
for descriptors belonging to an XDP specific queue.

This patch solves a bug in which, in case of a VF reset, the
descriptors aren\'t freed correctly, leading to crashes.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35960', '2024-11-24 09:01:55.235361', 'https://cve.circl.lu/cve/CVE-2024-35960', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 9.1, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

net/mlx5: Properly link new fs rules into the tree

Previously, add_rule_fg would only add newly created rules from the
handle into the tree when they had a refcount of 1. On the other hand,
create_flow_handle tries hard to find and reference already existing
identical rules instead of creating new ones.

These two behaviors can result in a situation where create_flow_handle
1) creates a new rule and references it, then
2) in a subsequent step during the same handle creation references it
   again,
resulting in a rule with a refcount of 2 that is not linked into the
tree, will have a NULL parent and root and will result in a crash when
the flow group is deleted because del_sw_hw_rule, invoked on rule
deletion, assumes node->parent is != NULL.

This happened in the wild, due to another bug related to incorrect
handling of duplicate pkt_reformat ids, which lead to the code in
create_flow_handle incorrectly referencing a just-added rule in the same
flow handle, resulting in the problem described above. Full details are
at [1].

This patch changes add_rule_fg to add new rules without parents into
the tree, properly initializing them and avoiding the crash. This makes
it more consistent with how rules are added to an FTE in
create_flow_handle.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35845', '2024-11-24 09:01:55.235362', 'https://cve.circl.lu/cve/CVE-2024-35845', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 9.1, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

wifi: iwlwifi: dbg-tlv: ensure NUL termination

The iwl_fw_ini_debug_info_tlv is used as a string, so we must
ensure the string is terminated correctly before using it.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47356', '2024-11-24 09:01:55.235362', 'https://cve.circl.lu/cve/CVE-2021-47356', 'Red Hat Update for kernel (RHSA-2024:6993)', 7.7, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

mISDN: fix possible use-after-free in HFC_cleanup()

This module\'s remove path calls del_timer(). However, that function
does not wait until the timer handler finishes. This means that the
timer handler may still be running after the driver\'s remove function
has finished, which would result in a use-after-free.

Fix by calling del_timer_sync(), which makes sure the timer handler
has finished, and unable to re-schedule itself.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47548', '2024-11-24 09:01:55.235370', 'https://cve.circl.lu/cve/CVE-2021-47548', 'Red Hat Update for kernel (RHSA-2024:5101)', 9.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

ethernet: hisilicon: hns: hns_dsaf_misc: fix a possible array overflow in hns_dsaf_ge_srst_by_port()

The if statement:
  if (port >= DSAF_GE_NUM)
        return;

limits the value of port less than DSAF_GE_NUM (i.e., 8).
However, if the value of port is 6 or 7, an array overflow could occur:
  port_rst_off = dsaf_dev->mac_cb[port]->port_rst_off;

because the length of dsaf_dev->mac_cb is DSAF_MAX_PORT_NUM (i.e., 6).

To fix this possible array overflow, we first check port and if it is
greater than or equal to DSAF_MAX_PORT_NUM, the function returns.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-36886', '2024-11-24 09:01:55.235370', 'https://cve.circl.lu/cve/CVE-2024-36886', 'Red Hat Update for kernel (RHSA-2024:5101)', 8.1, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

tipc: fix UAF in error path

Sam Page (sam4k) working with Trend Micro Zero Day Initiative reported
a UAF in the tipc_buf_append() error path:

BUG: KASAN: slab-use-after-free in kfree_skb_list_reason+0x47e/0x4c0
linux/net/core/skbuff.c:1183
Read of size 8 at addr ffff88804d2a7c80 by task poc/8034

CPU: 1 PID: 8034 Comm: poc Not tainted 6.8.2 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
1.16.0-debian-1.16.0-5 04/01/2014
Call Trace:
 <IRQ>
 __dump_stack linux/lib/dump_stack.c:88
 dump_stack_lvl+0xd9/0x1b0 linux/lib/dump_stack.c:106
 print_address_description linux/mm/kasan/report.c:377
 print_report+0xc4/0x620 linux/mm/kasan/report.c:488
 kasan_report+0xda/0x110 linux/mm/kasan/report.c:601
 kfree_skb_list_reason+0x47e/0x4c0 linux/net/core/skbuff.c:1183
 skb_release_data+0x5af/0x880 linux/net/core/skbuff.c:1026
 skb_release_all linux/net/core/skbuff.c:1094
 __kfree_skb linux/net/core/skbuff.c:1108
 kfree_skb_reason+0x12d/0x210 linux/net/core/skbuff.c:1144
 kfree_skb linux/./include/linux/skbuff.h:1244
 tipc_buf_append+0x425/0xb50 linux/net/tipc/msg.c:186
 tipc_link_input+0x224/0x7c0 linux/net/tipc/link.c:1324
 tipc_link_rcv+0x76e/0x2d70 linux/net/tipc/link.c:1824
 tipc_rcv+0x45f/0x10f0 linux/net/tipc/node.c:2159
 tipc_udp_recv+0x73b/0x8f0 linux/net/tipc/udp_media.c:390
 udp_queue_rcv_one_skb+0xad2/0x1850 linux/net/ipv4/udp.c:2108
 udp_queue_rcv_skb+0x131/0xb00 linux/net/ipv4/udp.c:2186
 udp_unicast_rcv_skb+0x165/0x3b0 linux/net/ipv4/udp.c:2346
 __udp4_lib_rcv+0x2594/0x3400 linux/net/ipv4/udp.c:2422
 ip_protocol_deliver_rcu+0x30c/0x4e0 linux/net/ipv4/ip_input.c:205
 ip_local_deliver_finish+0x2e4/0x520 linux/net/ipv4/ip_input.c:233
 NF_HOOK linux/./include/linux/netfilter.h:314
 NF_HOOK linux/./include/linux/netfilter.h:308
 ip_local_deliver+0x18e/0x1f0 linux/net/ipv4/ip_input.c:254
 dst_input linux/./include/net/dst.h:461
 ip_rcv_finish linux/net/ipv4/ip_input.c:449
 NF_HOOK linux/./include/linux/netfilter.h:314
 NF_HOOK linux/./include/linux/netfilter.h:308
 ip_rcv+0x2c5/0x5d0 linux/net/ipv4/ip_input.c:569
 __netif_receive_skb_one_core+0x199/0x1e0 linux/net/core/dev.c:5534
 __netif_receive_skb+0x1f/0x1c0 linux/net/core/dev.c:5648
 process_backlog+0x101/0x6b0 linux/net/core/dev.c:5976
 __napi_poll.constprop.0+0xba/0x550 linux/net/core/dev.c:6576
 napi_poll linux/net/core/dev.c:6645
 net_rx_action+0x95a/0xe90 linux/net/core/dev.c:6781
 __do_softirq+0x21f/0x8e7 linux/kernel/softirq.c:553
 do_softirq linux/kernel/softirq.c:454
 do_softirq+0xb2/0xf0 linux/kernel/softirq.c:441
 </IRQ>
 <TASK>
 __local_bh_enable_ip+0x100/0x120 linux/kernel/softirq.c:381
 local_bh_enable linux/./include/linux/bottom_half.h:33
 rcu_read_unlock_bh linux/./include/linux/rcupdate.h:851
 __dev_queue_xmit+0x871/0x3ee0 linux/net/core/dev.c:4378
 dev_queue_xmit linux/./include/linux/netdevice.h:3169
 neigh_hh_output linux/./include/net/neighbour.h:526
 neigh_output linux/./include/net/neighbour.h:540
 ip_finish_output2+0x169f/0x2550 linux/net/ipv4/ip_output.c:235
 __ip_finish_output linux/net/ipv4/ip_output.c:313
 __ip_finish_output+0x49e/0x950 linux/net/ipv4/ip_output.c:295
 ip_finish_output+0x31/0x310 linux/net/ipv4/ip_output.c:323
 NF_HOOK_COND linux/./include/linux/netfilter.h:303
 ip_output+0x13b/0x2a0 linux/net/ipv4/ip_output.c:433
 dst_output linux/./include/net/dst.h:451
 ip_local_out linux/net/ipv4/ip_output.c:129
 ip_send_skb+0x3e5/0x560 linux/net/ipv4/ip_output.c:1492
 udp_send_skb+0x73f/0x1530 linux/net/ipv4/udp.c:963
 udp_sendmsg+0x1a36/0x2b40 linux/net/ipv4/udp.c:1250
 inet_sendmsg+0x105/0x140 linux/net/ipv4/af_inet.c:850
 sock_sendmsg_nosec linux/net/socket.c:730
 __sock_sendmsg linux/net/socket.c:745
 __sys_sendto+0x42c/0x4e0 linux/net/socket.c:2191
 __do_sys_sendto linux/net/socket.c:2203
 __se_sys_sendto linux/net/socket.c:2199
 __x64_sys_sendto+0xe0/0x1c0 linux/net/socket.c:2199
 do_syscall_x64 linux/arch/x86/entry/common.c:52
 do_syscall_
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35853', '2024-11-24 09:01:55.235363', 'https://cve.circl.lu/cve/CVE-2024-35853', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 6.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

mlxsw: spectrum_acl_tcam: Fix memory leak during rehash

The rehash delayed work migrates filters from one region to another.
This is done by iterating over all chunks (all the filters with the same
priority) in the region and in each chunk iterating over all the
filters.

If the migration fails, the code tries to migrate the filters back to
the old region. However, the rollback itself can also fail in which case
another migration will be erroneously performed. Besides the fact that
this ping pong is not a very good idea, it also creates a problem.

Each virtual chunk references two chunks: The currently used one
(\'vchunk->chunk\') and a backup (\'vchunk->chunk2\'). During migration the
first holds the chunk we want to migrate filters to and the second holds
the chunk we are migrating filters from.

The code currently assumes - but does not verify - that the backup chunk
does not exist (NULL) if the currently used chunk does not reference the
target region. This assumption breaks when we are trying to rollback a
rollback, resulting in the backup chunk being overwritten and leaked
[1].

Fix by not rolling back a failed rollback and add a warning to avoid
future cases.

[1]
WARNING: CPU: 5 PID: 1063 at lib/parman.c:291 parman_destroy+0x17/0x20
Modules linked in:
CPU: 5 PID: 1063 Comm: kworker/5:11 Tainted: G        W          6.9.0-rc2-custom-00784-gc6a05c468a0b #14
Hardware name: Mellanox Technologies Ltd. MSN3700/VMOD0005, BIOS 5.11 01/06/2019
Workqueue: mlxsw_core mlxsw_sp_acl_tcam_vregion_rehash_work
RIP: 0010:parman_destroy+0x17/0x20
[...]
Call Trace:
 <TASK>
 mlxsw_sp_acl_atcam_region_fini+0x19/0x60
 mlxsw_sp_acl_tcam_region_destroy+0x49/0xf0
 mlxsw_sp_acl_tcam_vregion_rehash_work+0x1f1/0x470
 process_one_work+0x151/0x370
 worker_thread+0x2cb/0x3e0
 kthread+0xd0/0x100
 ret_from_fork+0x34/0x50
 ret_from_fork_asm+0x1a/0x30
 </TASK>', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52703', '2024-11-24 09:01:55.235364', 'https://cve.circl.lu/cve/CVE-2023-52703', 'Red Hat Update for kernel (RHSA-2024:4211)', 3.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

net/usb: kalmia: Don\'t pass act_len in usb_bulk_msg error path

syzbot reported that act_len in kalmia_send_init_packet() is
uninitialized when passing it to the first usb_bulk_msg error path. Jiri
Pirko noted that it\'s pointless to pass it in the error path, and that
the value that would be printed in the second error path would be the
value of act_len from the first call to usb_bulk_msg.[1]

With this in mind, let\'s just not pass act_len to the usb_bulk_msg error
paths.

1: https://lore.kernel.org/lkml/Y9pY61y1nwTuzMOa@nanopsycho/', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52700', '2024-11-24 09:01:55.235364', 'https://cve.circl.lu/cve/CVE-2023-52700', 'Red Hat Update for kernel (RHSA-2024:4211)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

tipc: fix kernel warning when sending SYN message

When sending a SYN message, this kernel stack trace is observed:

...
[   13.396352] RIP: 0010:_copy_from_iter+0xb4/0x550
...
[   13.398494] Call Trace:
[   13.398630]  <TASK>
[   13.398630]  ? __alloc_skb+0xed/0x1a0
[   13.398630]  tipc_msg_build+0x12c/0x670 [tipc]
[   13.398630]  ? shmem_add_to_page_cache.isra.71+0x151/0x290
[   13.398630]  __tipc_sendmsg+0x2d1/0x710 [tipc]
[   13.398630]  ? tipc_connect+0x1d9/0x230 [tipc]
[   13.398630]  ? __local_bh_enable_ip+0x37/0x80
[   13.398630]  tipc_connect+0x1d9/0x230 [tipc]
[   13.398630]  ? __sys_connect+0x9f/0xd0
[   13.398630]  __sys_connect+0x9f/0xd0
[   13.398630]  ? preempt_count_add+0x4d/0xa0
[   13.398630]  ? fpregs_assert_state_consistent+0x22/0x50
[   13.398630]  __x64_sys_connect+0x16/0x20
[   13.398630]  do_syscall_64+0x42/0x90
[   13.398630]  entry_SYSCALL_64_after_hwframe+0x63/0xcd

It is because commit a41dad905e5a ("iov_iter: saner checks for attempt
to copy to/from iterator") has introduced sanity check for copying
from/to iov iterator. Lacking of copy direction from the iterator
viewpoint would lead to kernel stack trace like above.

This commit fixes this issue by initializing the iov iterator with
the correct copy direction when sending SYN or ACK without data.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35835', '2024-11-24 09:01:55.235365', 'https://cve.circl.lu/cve/CVE-2024-35835', 'Red Hat Update for kernel (RHSA-2024:4211)', 5.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

net/mlx5e: fix a double-free in arfs_create_groups

When `in` allocated by kvzalloc fails, arfs_create_groups will free
ft->g and return an error. However, arfs_create_table, the only caller of
arfs_create_groups, will hold this error and call to
mlx5e_destroy_flow_table, in which the ft->g will be freed again.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35854', '2024-11-24 09:01:55.235366', 'https://cve.circl.lu/cve/CVE-2024-35854', 'Red Hat Update for kernel (RHSA-2024:4211)', 8.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

mlxsw: spectrum_acl_tcam: Fix possible use-after-free during rehash

The rehash delayed work migrates filters from one region to another
according to the number of available credits.

The migrated from region is destroyed at the end of the work if the
number of credits is non-negative as the assumption is that this is
indicative of migration being complete. This assumption is incorrect as
a non-negative number of credits can also be the result of a failed
migration.

The destruction of a region that still has filters referencing it can
result in a use-after-free [1].

Fix by not destroying the region if migration failed.

[1]
BUG: KASAN: slab-use-after-free in mlxsw_sp_acl_ctcam_region_entry_remove+0x21d/0x230
Read of size 8 at addr ffff8881735319e8 by task kworker/0:31/3858

CPU: 0 PID: 3858 Comm: kworker/0:31 Tainted: G        W          6.9.0-rc2-custom-00782-gf2275c2157d8 #5
Hardware name: Mellanox Technologies Ltd. MSN3700/VMOD0005, BIOS 5.11 01/06/2019
Workqueue: mlxsw_core mlxsw_sp_acl_tcam_vregion_rehash_work
Call Trace:
 <TASK>
 dump_stack_lvl+0xc6/0x120
 print_report+0xce/0x670
 kasan_report+0xd7/0x110
 mlxsw_sp_acl_ctcam_region_entry_remove+0x21d/0x230
 mlxsw_sp_acl_ctcam_entry_del+0x2e/0x70
 mlxsw_sp_acl_atcam_entry_del+0x81/0x210
 mlxsw_sp_acl_tcam_vchunk_migrate_all+0x3cd/0xb50
 mlxsw_sp_acl_tcam_vregion_rehash_work+0x157/0x1300
 process_one_work+0x8eb/0x19b0
 worker_thread+0x6c9/0xf70
 kthread+0x2c9/0x3b0
 ret_from_fork+0x4d/0x80
 ret_from_fork_asm+0x1a/0x30
 </TASK>

Allocated by task 174:
 kasan_save_stack+0x33/0x60
 kasan_save_track+0x14/0x30
 __kasan_kmalloc+0x8f/0xa0
 __kmalloc+0x19c/0x360
 mlxsw_sp_acl_tcam_region_create+0xdf/0x9c0
 mlxsw_sp_acl_tcam_vregion_rehash_work+0x954/0x1300
 process_one_work+0x8eb/0x19b0
 worker_thread+0x6c9/0xf70
 kthread+0x2c9/0x3b0
 ret_from_fork+0x4d/0x80
 ret_from_fork_asm+0x1a/0x30

Freed by task 7:
 kasan_save_stack+0x33/0x60
 kasan_save_track+0x14/0x30
 kasan_save_free_info+0x3b/0x60
 poison_slab_object+0x102/0x170
 __kasan_slab_free+0x14/0x30
 kfree+0xc1/0x290
 mlxsw_sp_acl_tcam_region_destroy+0x272/0x310
 mlxsw_sp_acl_tcam_vregion_rehash_work+0x731/0x1300
 process_one_work+0x8eb/0x19b0
 worker_thread+0x6c9/0xf70
 kthread+0x2c9/0x3b0
 ret_from_fork+0x4d/0x80
 ret_from_fork_asm+0x1a/0x30', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47456', '2024-11-24 09:01:55.235366', 'https://cve.circl.lu/cve/CVE-2021-47456', 'Red Hat Update for kernel (RHSA-2024:4211)', 8.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

can: peak_pci: peak_pci_remove(): fix UAF

When remove the module peek_pci, referencing \'chan\' again after
releasing \'dev\' will cause UAF.

Fix this by releasing \'dev\' later.

The following log reveals it:

[   35.961814 ] BUG: KASAN: use-after-free in peak_pci_remove+0x16f/0x270 [peak_pci]
[   35.963414 ] Read of size 8 at addr ffff888136998ee8 by task modprobe/5537
[   35.965513 ] Call Trace:
[   35.965718 ]  dump_stack_lvl+0xa8/0xd1
[   35.966028 ]  print_address_description+0x87/0x3b0
[   35.966420 ]  kasan_report+0x172/0x1c0
[   35.966725 ]  ? peak_pci_remove+0x16f/0x270 [peak_pci]
[   35.967137 ]  ? trace_irq_enable_rcuidle+0x10/0x170
[   35.967529 ]  ? peak_pci_remove+0x16f/0x270 [peak_pci]
[   35.967945 ]  __asan_report_load8_noabort+0x14/0x20
[   35.968346 ]  peak_pci_remove+0x16f/0x270 [peak_pci]
[   35.968752 ]  pci_device_remove+0xa9/0x250', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35870', '2024-11-24 09:01:55.235367', 'https://cve.circl.lu/cve/CVE-2024-35870', 'Red Hat Update for kernel (RHSA-2024:4349)', 4.4, 'Medium', e'In the Linux kernel, the following vulnerability has been resolved:

smb: client: fix UAF in smb2_reconnect_server()

The UAF bug is due to smb2_reconnect_server() accessing a session that
is already being teared down by another thread that is executing
__cifs_put_smb_ses().  This can happen when (a) the client has
connection to the server but no session or (b) another thread ends up
setting @ses->ses_status again to something different than
SES_EXITING.

To fix this, we need to make sure to unconditionally set
@ses->ses_status to SES_EXITING and prevent any other threads from
setting a new status while we\'re still tearing it down.

The following can be reproduced by adding some delay to right after
the ipc is freed in __cifs_put_smb_ses() - which will give
smb2_reconnect_server() worker a chance to run and then accessing
@ses->ipc:

kinit ...
mount.cifs //srv/share /mnt/1 -o sec=krb5,nohandlecache,echo_interval=10
[disconnect srv]
ls /mnt/1 &>/dev/null
sleep 30
kdestroy
[reconnect srv]
sleep 10
umount /mnt/1
...
CIFS: VFS: Verify user has a krb5 ticket and keyutils is installed
CIFS: VFS: \\\\srv Send error in SessSetup = -126
CIFS: VFS: Verify user has a krb5 ticket and keyutils is installed
CIFS: VFS: \\\\srv Send error in SessSetup = -126
general protection fault, probably for non-canonical address
0x6b6b6b6b6b6b6b6b: 0000 [#1] PREEMPT SMP NOPTI
CPU: 3 PID: 50 Comm: kworker/3:1 Not tainted 6.9.0-rc2 #1
Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-1.fc39
04/01/2014
Workqueue: cifsiod smb2_reconnect_server [cifs]
RIP: 0010:__list_del_entry_valid_or_report+0x33/0xf0
Code: 4f 08 48 85 d2 74 42 48 85 c9 74 59 48 b8 00 01 00 00 00 00 ad
de 48 39 c2 74 61 48 b8 22 01 00 00 00 00 74 69 <48> 8b 01 48 39 f8 75
7b 48 8b 72 08 48 39 c6 0f 85 88 00 00 00 b8
RSP: 0018:ffffc900001bfd70 EFLAGS: 00010a83
RAX: dead000000000122 RBX: ffff88810da53838 RCX: 6b6b6b6b6b6b6b6b
RDX: 6b6b6b6b6b6b6b6b RSI: ffffffffc02f6878 RDI: ffff88810da53800
RBP: ffff88810da53800 R08: 0000000000000001 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000001 R12: ffff88810c064000
R13: 0000000000000001 R14: ffff88810c064000 R15: ffff8881039cc000
FS: 0000000000000000(0000) GS:ffff888157c00000(0000)
knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007fe3728b1000 CR3: 000000010caa4000 CR4: 0000000000750ef0
PKRU: 55555554
Call Trace:
 <TASK>
 ? die_addr+0x36/0x90
 ? exc_general_protection+0x1c1/0x3f0
 ? asm_exc_general_protection+0x26/0x30
 ? __list_del_entry_valid_or_report+0x33/0xf0
 __cifs_put_smb_ses+0x1ae/0x500 [cifs]
 smb2_reconnect_server+0x4ed/0x710 [cifs]
 process_one_work+0x205/0x6b0
 worker_thread+0x191/0x360
 ? __pfx_worker_thread+0x10/0x10
 kthread+0xe2/0x110
 ? __pfx_kthread+0x10/0x10
 ret_from_fork+0x34/0x50
 ? __pfx_kthread+0x10/0x10
 ret_from_fork_asm+0x1a/0x30
 </TASK>', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27393', '2024-11-24 09:01:55.235368', 'https://cve.circl.lu/cve/CVE-2024-27393', 'Red Hat Update for kernel (RHSA-2024:4349)', 5.5, 'Medium', e'In the Linux kernel, the following vulnerability has been resolved:

xen-netfront: Add missing skb_mark_for_recycle

Notice that skb_mark_for_recycle() is introduced later than fixes tag in
commit 6a5bcd84e886 ("page_pool: Allow drivers to hint on SKB recycling").

It is believed that fixes tag were missing a call to page_pool_release_page()
between v5.9 to v5.14, after which is should have used skb_mark_for_recycle().
Since v6.6 the call page_pool_release_page() were removed (in
commit 535b9c61bdef ("net: page_pool: hide page_pool_release_page()")
and remaining callers converted (in commit 6bfef2ec0172 ("Merge branch
\'net-page_pool-remove-page_pool_release_page\'")).

This leak became visible in v6.8 via commit dba1b8a7ab68 ("mm/page_pool: catch
page_pool memory leaks").', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27435', '2024-11-24 09:01:55.235371', 'https://cve.circl.lu/cve/CVE-2024-27435', 'Red Hat Update for kernel (RHSA-2024:4583)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

nvme: fix reconnection fail due to reserved tag allocation

We found a issue on production environment while using NVMe over RDMA,
admin_q reconnect failed forever while remote target and network is ok.
After dig into it, we found it may caused by a ABBA deadlock due to tag
allocation. In my case, the tag was hold by a keep alive request
waiting inside admin_q, as we quiesced admin_q while reset ctrl, so the
request maked as idle and will not process before reset success. As
fabric_q shares tagset with admin_q, while reconnect remote target, we
need a tag for connect command, but the only one reserved tag was held
by keep alive command which waiting inside admin_q. As a result, we
failed to reconnect admin_q forever. In order to fix this issue, I
think we should keep two reserved tags for admin queue.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35857', '2024-11-24 09:01:55.235372', 'https://cve.circl.lu/cve/CVE-2024-35857', 'Red Hat Update for kernel (RHSA-2024:4928)', 5.3, 'Medium', e'In the Linux kernel, the following vulnerability has been resolved:

icmp: prevent possible NULL dereferences from icmp_build_probe()

First problem is a double call to __in_dev_get_rcu(), because
the second one could return NULL.

if (__in_dev_get_rcu(dev) && __in_dev_get_rcu(dev)->ifa_list)

Second problem is a read from dev->ip6_ptr with no NULL check:

if (!list_empty(&rcu_dereference(dev->ip6_ptr)->addr_list))

Use the correct RCU API to fix these.

v2: add missing include <net/addrconf.h>', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26880', '2024-11-24 09:01:55.235372', 'https://cve.circl.lu/cve/CVE-2024-26880', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 6.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

dm: call the resume method on internal suspend

There is this reported crash when experimenting with the lvm2 testsuite.
The list corruption is caused by the fact that the postsuspend and resume
methods were not paired correctly; there were two consecutive calls to the
origin_postsuspend function. The second call attempts to remove the
"hash_list" entry from a list, while it was already removed by the first
call.

Fix __dm_internal_resume so that it calls the preresume and resume
methods of the table\'s targets.

If a preresume method of some target fails, we are in a tricky situation.
We can\'t return an error because dm_internal_resume isn\'t supposed to
return errors. We can\'t return success, because then the "resume" and
"postsuspend" methods would not be paired correctly. So, we set the
DMF_SUSPENDED flag and we fake normal suspend - it may confuse userspace
tools, but it won\'t cause a kernel crash.

------------[ cut here ]------------
kernel BUG at lib/list_debug.c:56!
invalid opcode: 0000 [#1] PREEMPT SMP
CPU: 1 PID: 8343 Comm: dmsetup Not tainted 6.8.0-rc6 #4
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
RIP: 0010:__list_del_entry_valid_or_report+0x77/0xc0
<snip>
RSP: 0018:ffff8881b831bcc0 EFLAGS: 00010282
RAX: 000000000000004e RBX: ffff888143b6eb80 RCX: 0000000000000000
RDX: 0000000000000001 RSI: ffffffff819053d0 RDI: 00000000ffffffff
RBP: ffff8881b83a3400 R08: 00000000fffeffff R09: 0000000000000058
R10: 0000000000000000 R11: ffffffff81a24080 R12: 0000000000000001
R13: ffff88814538e000 R14: ffff888143bc6dc0 R15: ffffffffa02e4bb0
FS:  00000000f7c0f780(0000) GS:ffff8893f0a40000(0000) knlGS:0000000000000000
CS:  0010 DS: 002b ES: 002b CR0: 0000000080050033
CR2: 0000000057fb5000 CR3: 0000000143474000 CR4: 00000000000006b0
Call Trace:
 <TASK>
 ? die+0x2d/0x80
 ? do_trap+0xeb/0xf0
 ? __list_del_entry_valid_or_report+0x77/0xc0
 ? do_error_trap+0x60/0x80
 ? __list_del_entry_valid_or_report+0x77/0xc0
 ? exc_invalid_op+0x49/0x60
 ? __list_del_entry_valid_or_report+0x77/0xc0
 ? asm_exc_invalid_op+0x16/0x20
 ? table_deps+0x1b0/0x1b0 [dm_mod]
 ? __list_del_entry_valid_or_report+0x77/0xc0
 origin_postsuspend+0x1a/0x50 [dm_snapshot]
 dm_table_postsuspend_targets+0x34/0x50 [dm_mod]
 dm_suspend+0xd8/0xf0 [dm_mod]
 dev_suspend+0x1f2/0x2f0 [dm_mod]
 ? table_deps+0x1b0/0x1b0 [dm_mod]
 ctl_ioctl+0x300/0x5f0 [dm_mod]
 dm_compat_ctl_ioctl+0x7/0x10 [dm_mod]
 __x64_compat_sys_ioctl+0x104/0x170
 do_syscall_64+0x184/0x1b0
 entry_SYSCALL_64_after_hwframe+0x46/0x4e
RIP: 0033:0xf7e6aead
<snip>
---[ end trace 0000000000000000 ]---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2022-48743', '2024-11-24 09:01:55.235373', 'https://cve.circl.lu/cve/CVE-2022-48743', 'Red Hat Update for kernel (RHSA-2024:6206)', 5.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

net: amd-xgbe: Fix skb data length underflow

There will be BUG_ON() triggered in include/linux/skbuff.h leading to
intermittent kernel panic, when the skb length underflow is detected.

Fix this by dropping the packet if such length underflows are seen
because of inconsistencies in the hardware descriptors.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52653', '2024-11-24 09:01:55.235374', 'https://cve.circl.lu/cve/CVE-2023-52653', 'Red Hat Update for kernel (RHSA-2024:5101)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

SUNRPC: fix a memleak in gss_import_v2_context

The ctx->mech_used.data allocated by kmemdup is not freed in neither
gss_import_v2_context nor it only caller gss_krb5_import_sec_context,
which frees ctx on error.

Thus, this patch reform the last call of gss_import_v2_context to the
gss_krb5_import_ctx_v2, preventing the memleak while keepping the return
formation.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52623', '2024-11-24 09:01:55.235374', 'https://cve.circl.lu/cve/CVE-2023-52623', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6767-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

SUNRPC: Fix a suspicious RCU usage warning

I received the following warning while running cthon against an ontap
server running pNFS:

[   57.202521] =============================
[   57.202522] WARNING: suspicious RCU usage
[   57.202523] 6.7.0-rc3-g2cc14f52aeb7 #41492 Not tainted
[   57.202525] -----------------------------
[   57.202525] net/sunrpc/xprtmultipath.c:349 RCU-list traversed in non-reader section!!
[   57.202527]
               other info that might help us debug this:

[   57.202528]
               rcu_scheduler_active = 2, debug_locks = 1
[   57.202529] no locks held by test5/3567.
[   57.202530]
               stack backtrace:
[   57.202532] CPU: 0 PID: 3567 Comm: test5 Not tainted 6.7.0-rc3-g2cc14f52aeb7 #41492 5b09971b4965c0aceba19f3eea324a4a806e227e
[   57.202534] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS unknown 2/2/2022
[   57.202536] Call Trace:
[   57.202537]  <TASK>
[   57.202540]  dump_stack_lvl+0x77/0xb0
[   57.202551]  lockdep_rcu_suspicious+0x154/0x1a0
[   57.202556]  rpc_xprt_switch_has_addr+0x17c/0x190 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6]
[   57.202596]  rpc_clnt_setup_test_and_add_xprt+0x50/0x180 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6]
[   57.202621]  ? rpc_clnt_add_xprt+0x254/0x300 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6]
[   57.202646]  rpc_clnt_add_xprt+0x27a/0x300 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6]
[   57.202671]  ? __pfx_rpc_clnt_setup_test_and_add_xprt+0x10/0x10 [sunrpc ebe02571b9a8ceebf7d98e71675af20c19bdb1f6]
[   57.202696]  nfs4_pnfs_ds_connect+0x345/0x760 [nfsv4 c716d88496ded0ea6d289bbea684fa996f9b57a9]
[   57.202728]  ? __pfx_nfs4_test_session_trunk+0x10/0x10 [nfsv4 c716d88496ded0ea6d289bbea684fa996f9b57a9]
[   57.202754]  nfs4_fl_prepare_ds+0x75/0xc0 [nfs_layout_nfsv41_files e3a4187f18ae8a27b630f9feae6831b584a9360a]
[   57.202760]  filelayout_write_pagelist+0x4a/0x200 [nfs_layout_nfsv41_files e3a4187f18ae8a27b630f9feae6831b584a9360a]
[   57.202765]  pnfs_generic_pg_writepages+0xbe/0x230 [nfsv4 c716d88496ded0ea6d289bbea684fa996f9b57a9]
[   57.202788]  __nfs_pageio_add_request+0x3fd/0x520 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902]
[   57.202813]  nfs_pageio_add_request+0x18b/0x390 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902]
[   57.202831]  nfs_do_writepage+0x116/0x1e0 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902]
[   57.202849]  nfs_writepages_callback+0x13/0x30 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902]
[   57.202866]  write_cache_pages+0x265/0x450
[   57.202870]  ? __pfx_nfs_writepages_callback+0x10/0x10 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902]
[   57.202891]  nfs_writepages+0x141/0x230 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902]
[   57.202913]  do_writepages+0xd2/0x230
[   57.202917]  ? filemap_fdatawrite_wbc+0x5c/0x80
[   57.202921]  filemap_fdatawrite_wbc+0x67/0x80
[   57.202924]  filemap_write_and_wait_range+0xd9/0x170
[   57.202930]  nfs_wb_all+0x49/0x180 [nfs 6c976fa593a7c2976f5a0aeb4965514a828e6902]
[   57.202947]  nfs4_file_flush+0x72/0xb0 [nfsv4 c716d88496ded0ea6d289bbea684fa996f9b57a9]
[   57.202969]  __se_sys_close+0x46/0xd0
[   57.202972]  do_syscall_64+0x68/0x100
[   57.202975]  ? do_syscall_64+0x77/0x100
[   57.202976]  ? do_syscall_64+0x77/0x100
[   57.202979]  entry_SYSCALL_64_after_hwframe+0x6e/0x76
[   57.202982] RIP: 0033:0x7fe2b12e4a94
[   57.202985] Code: 00 f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f 84 00 00 00 00 00 90 f3 0f 1e fa 80 3d d5 18 0e 00 00 74 13 b8 03 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 44 c3 0f 1f 00 48 83 ec 18 89 7c 24 0c e8 c3
[   57.202987] RSP: 002b:00007ffe857ddb38 EFLAGS: 00000202 ORIG_RAX: 0000000000000003
[   57.202989] RAX: ffffffffffffffda RBX: 00007ffe857dfd68 RCX: 00007fe2b12e4a94
[   57.202991] RDX: 0000000000002000 RSI: 00007ffe857ddc40 RDI: 0000000000000003
[   57.202992] RBP: 00007ffe857dfc50 R08: 7fffffffffffffff R09: 0000000065650f49
[   57.202993] R10: 00007f
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35910', '2024-11-24 09:01:55.235375', 'https://cve.circl.lu/cve/CVE-2024-35910', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

tcp: properly terminate timers for kernel sockets

We had various syzbot reports about tcp timers firing after
the corresponding netns has been dismantled.

Fortunately Josef Bacik could trigger the issue more often,
and could test a patch I wrote two years ago.

When TCP sockets are closed, we call inet_csk_clear_xmit_timers()
to \'stop\' the timers.

inet_csk_clear_xmit_timers() can be called from any context,
including when socket lock is held.
This is the reason it uses sk_stop_timer(), aka del_timer().
This means that ongoing timers might finish much later.

For user sockets, this is fine because each running timer
holds a reference on the socket, and the user socket holds
a reference on the netns.

For kernel sockets, we risk that the netns is freed before
timer can complete, because kernel sockets do not hold
reference on the netns.

This patch adds inet_csk_clear_xmit_timers_sync() function
that using sk_stop_timer_sync() to make sure all timers
are terminated before the kernel socket is released.
Modules using kernel sockets close them in their netns exit()
handler.

Also add sock_not_owned_by_me() helper to get LOCKDEP
support : inet_csk_clear_xmit_timers_sync() must not be called
while socket lock is held.

It is very possible we can revert in the future commit
3a58f13a881e ("net: rds: acquire refcount on TCP sockets")
which attempted to solve the issue in rds only.
(net/smc/af_smc.c and net/mptcp/subflow.c have similar code)

We probably can remove the check_net() tests from
tcp_out_of_resources() and __tcp_close() in the future.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35899', '2024-11-24 09:01:55.235375', 'https://cve.circl.lu/cve/CVE-2024-35899', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 6.1, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

netfilter: nf_tables: flush pending destroy work before exit_net release

Similar to 2c9f0293280e ("netfilter: nf_tables: flush pending destroy
work before netlink notifier") to address a race between exit_net and
the destroy workqueue.

The trace below shows an element to be released via destroy workqueue
while exit_net path (triggered via module removal) has already released
the set that is used in such transaction.

[ 1360.547789] BUG: KASAN: slab-use-after-free in nf_tables_trans_destroy_work+0x3f5/0x590 [nf_tables]
[ 1360.547861] Read of size 8 at addr ffff888140500cc0 by task kworker/4:1/152465
[ 1360.547870] CPU: 4 PID: 152465 Comm: kworker/4:1 Not tainted 6.8.0+ #359
[ 1360.547882] Workqueue: events nf_tables_trans_destroy_work [nf_tables]
[ 1360.547984] Call Trace:
[ 1360.547991]  <TASK>
[ 1360.547998]  dump_stack_lvl+0x53/0x70
[ 1360.548014]  print_report+0xc4/0x610
[ 1360.548026]  ? __virt_addr_valid+0xba/0x160
[ 1360.548040]  ? __pfx__raw_spin_lock_irqsave+0x10/0x10
[ 1360.548054]  ? nf_tables_trans_destroy_work+0x3f5/0x590 [nf_tables]
[ 1360.548176]  kasan_report+0xae/0xe0
[ 1360.548189]  ? nf_tables_trans_destroy_work+0x3f5/0x590 [nf_tables]
[ 1360.548312]  nf_tables_trans_destroy_work+0x3f5/0x590 [nf_tables]
[ 1360.548447]  ? __pfx_nf_tables_trans_destroy_work+0x10/0x10 [nf_tables]
[ 1360.548577]  ? _raw_spin_unlock_irq+0x18/0x30
[ 1360.548591]  process_one_work+0x2f1/0x670
[ 1360.548610]  worker_thread+0x4d3/0x760
[ 1360.548627]  ? __pfx_worker_thread+0x10/0x10
[ 1360.548640]  kthread+0x16b/0x1b0
[ 1360.548653]  ? __pfx_kthread+0x10/0x10
[ 1360.548665]  ret_from_fork+0x2f/0x50
[ 1360.548679]  ? __pfx_kthread+0x10/0x10
[ 1360.548690]  ret_from_fork_asm+0x1a/0x30
[ 1360.548707]  </TASK>

[ 1360.548719] Allocated by task 192061:
[ 1360.548726]  kasan_save_stack+0x20/0x40
[ 1360.548739]  kasan_save_track+0x14/0x30
[ 1360.548750]  __kasan_kmalloc+0x8f/0xa0
[ 1360.548760]  __kmalloc_node+0x1f1/0x450
[ 1360.548771]  nf_tables_newset+0x10c7/0x1b50 [nf_tables]
[ 1360.548883]  nfnetlink_rcv_batch+0xbc4/0xdc0 [nfnetlink]
[ 1360.548909]  nfnetlink_rcv+0x1a8/0x1e0 [nfnetlink]
[ 1360.548927]  netlink_unicast+0x367/0x4f0
[ 1360.548935]  netlink_sendmsg+0x34b/0x610
[ 1360.548944]  ____sys_sendmsg+0x4d4/0x510
[ 1360.548953]  ___sys_sendmsg+0xc9/0x120
[ 1360.548961]  __sys_sendmsg+0xbe/0x140
[ 1360.548971]  do_syscall_64+0x55/0x120
[ 1360.548982]  entry_SYSCALL_64_after_hwframe+0x55/0x5d

[ 1360.548994] Freed by task 192222:
[ 1360.548999]  kasan_save_stack+0x20/0x40
[ 1360.549009]  kasan_save_track+0x14/0x30
[ 1360.549019]  kasan_save_free_info+0x3b/0x60
[ 1360.549028]  poison_slab_object+0x100/0x180
[ 1360.549036]  __kasan_slab_free+0x14/0x30
[ 1360.549042]  kfree+0xb6/0x260
[ 1360.549049]  __nft_release_table+0x473/0x6a0 [nf_tables]
[ 1360.549131]  nf_tables_exit_net+0x170/0x240 [nf_tables]
[ 1360.549221]  ops_exit_list+0x50/0xa0
[ 1360.549229]  free_exit_list+0x101/0x140
[ 1360.549236]  unregister_pernet_operations+0x107/0x160
[ 1360.549245]  unregister_pernet_subsys+0x1c/0x30
[ 1360.549254]  nf_tables_module_exit+0x43/0x80 [nf_tables]
[ 1360.549345]  __do_sys_delete_module+0x253/0x370
[ 1360.549352]  do_syscall_64+0x55/0x120
[ 1360.549360]  entry_SYSCALL_64_after_hwframe+0x55/0x5d

(gdb) list *__nft_release_table+0x473
0x1e033 is in __nft_release_table (net/netfilter/nf_tables_api.c:11354).
11349           list_for_each_entry_safe(flowtable, nf, &table->flowtables, list) {
11350                   list_del(&flowtable->list);
11351                   nft_use_dec(&table->use);
11352                   nf_tables_flowtable_destroy(flowtable);
11353           }
11354           list_for_each_entry_safe(set, ns, &table->sets, list) {
11355                   list_del(&set->list);
11356                   nft_use_dec(&table->use);
11357                   if (set->flags & (NFT_SET_MAP | NFT_SET_OBJECT))
11358                           nft_map_deactivat
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52811', '2024-11-24 09:01:55.235388', 'https://cve.circl.lu/cve/CVE-2023-52811', 'Red Hat Update for kernel (RHSA-2024:6993)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

scsi: ibmvfc: Remove BUG_ON in the case of an empty event pool

In practice the driver should never send more commands than are allocated
to a queue\'s event pool. In the unlikely event that this happens, the code
asserts a BUG_ON, and in the case that the kernel is not configured to
crash on panic returns a junk event pointer from the empty event list
causing things to spiral from there. This BUG_ON is a historical artifact
of the ibmvfc driver first being upstreamed, and it is well known now that
the use of BUG_ON is bad practice except in the most unrecoverable
scenario. There is nothing about this scenario that prevents the driver
from recovering and carrying on.

Remove the BUG_ON in question from ibmvfc_get_event() and return a NULL
pointer in the case of an empty event pool. Update all call sites to
ibmvfc_get_event() to check for a NULL pointer and perfrom the appropriate
failure or recovery action.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35824', '2024-11-24 09:01:55.235376', 'https://cve.circl.lu/cve/CVE-2024-35824', 'Red Hat Update for kernel (RHSA-2024:5101)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

misc: lis3lv02d_i2c: Fix regulators getting en-/dis-abled twice on suspend/resume

When not configured for wakeup lis3lv02d_i2c_suspend() will call
lis3lv02d_poweroff() even if the device has already been turned off
by the runtime-suspend handler and if configured for wakeup and
the device is runtime-suspended at this point then it is not turned
back on to serve as a wakeup source.

Before commit b1b9f7a49440 ("misc: lis3lv02d_i2c: Add missing setting
of the reg_ctrl callback"), lis3lv02d_poweroff() failed to disable
the regulators which as a side effect made calling poweroff() twice ok.

Now that poweroff() correctly disables the regulators, doing this twice
triggers a WARN() in the regulator core:

unbalanced disables for regulator-dummy
WARNING: CPU: 1 PID: 92 at drivers/regulator/core.c:2999 _regulator_disable
...

Fix lis3lv02d_i2c_suspend() to not call poweroff() a second time if
already runtime-suspended and add a poweron() call when necessary to
make wakeup work.

lis3lv02d_i2c_resume() has similar issues, with an added weirness that
it always powers on the device if it is runtime suspended, after which
the first runtime-resume will call poweron() again, causing the enabled
count for the regulator to increase by 1 every suspend/resume. These
unbalanced regulator_enable() calls cause the regulator to never
be turned off and trigger the following WARN() on driver unbind:

WARNING: CPU: 1 PID: 1724 at drivers/regulator/core.c:2396 _regulator_put

Fix this by making lis3lv02d_i2c_resume() mirror the new suspend().', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35823', '2024-11-24 09:01:55.235377', 'https://cve.circl.lu/cve/CVE-2024-35823', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

vt: fix unicode buffer corruption when deleting characters

This is the same issue that was fixed for the VGA text buffer in commit
39cdb68c64d8 ("vt: fix memory overlapping when deleting chars in the
buffer"). The cure is also the same i.e. replace memcpy() with memmove()
due to the overlaping buffers.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35814', '2024-11-24 09:01:55.235377', 'https://cve.circl.lu/cve/CVE-2024-35814', 'Red Hat Update for kernel (RHSA-2024:5101)', 7.1, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

swiotlb: Fix double-allocation of slots due to broken alignment handling

Commit bbb73a103fbb ("swiotlb: fix a braino in the alignment check fix"),
which was a fix for commit 0eee5ae10256 ("swiotlb: fix slot alignment
checks"), causes a functional regression with vsock in a virtual machine
using bouncing via a restricted DMA SWIOTLB pool.

When virtio allocates the virtqueues for the vsock device using
dma_alloc_coherent(), the SWIOTLB search can return page-unaligned
allocations if \'area->index\' was left unaligned by a previous allocation
from the buffer:

 # Final address in brackets is the SWIOTLB address returned to the caller
 | virtio-pci 0000:00:07.0: orig_addr 0x0 alloc_size 0x2000, iotlb_align_mask 0x800 stride 0x2: got slot 1645-1649/7168 (0x98326800)
 | virtio-pci 0000:00:07.0: orig_addr 0x0 alloc_size 0x2000, iotlb_align_mask 0x800 stride 0x2: got slot 1649-1653/7168 (0x98328800)
 | virtio-pci 0000:00:07.0: orig_addr 0x0 alloc_size 0x2000, iotlb_align_mask 0x800 stride 0x2: got slot 1653-1657/7168 (0x9832a800)

This ends badly (typically buffer corruption and/or a hang) because
swiotlb_alloc() is expecting a page-aligned allocation and so blindly
returns a pointer to the \'struct page\' corresponding to the allocation,
therefore double-allocating the first half (2KiB slot) of the 4KiB page.

Fix the problem by treating the allocation alignment separately to any
additional alignment requirements from the device, using the maximum
of the two as the stride to search the buffer slots and taking care
to ensure a minimum of page-alignment for buffers larger than a page.

This also resolves swiotlb allocation failures occuring due to the
inclusion of ~PAGE_MASK in \'iotlb_align_mask\' for large allocations and
resulting in alignment requirements exceeding swiotlb_max_mapping_size().', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35801', '2024-11-24 09:01:55.235378', 'https://cve.circl.lu/cve/CVE-2024-35801', 'Red Hat Update for kernel (RHSA-2024:5101)', 7.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

x86/fpu: Keep xfd_state in sync with MSR_IA32_XFD

Commit 672365477ae8 ("x86/fpu: Update XFD state where required") and
commit 8bf26758ca96 ("x86/fpu: Add XFD state to fpstate") introduced a
per CPU variable xfd_state to keep the MSR_IA32_XFD value cached, in
order to avoid unnecessary writes to the MSR.

On CPU hotplug MSR_IA32_XFD is reset to the init_fpstate.xfd, which
wipes out any stale state. But the per CPU cached xfd value is not
reset, which brings them out of sync.

As a consequence a subsequent xfd_update_state() might fail to update
the MSR which in turn can result in XRSTOR raising a #NM in kernel
space, which crashes the kernel.

To fix this, introduce xfd_set_state() to write xfd_state together
with MSR_IA32_XFD, and use it in all places that set MSR_IA32_XFD.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27020', '2024-11-24 09:01:55.235379', 'https://cve.circl.lu/cve/CVE-2024-27020', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 7, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get()

nft_unregister_expr() can concurrent with __nft_expr_type_get(),
and there is not any protection when iterate over nf_tables_expressions
list in __nft_expr_type_get(). Therefore, there is potential data-race
of nf_tables_expressions list entry.

Use list_for_each_entry_rcu() to iterate over nf_tables_expressions
list in __nft_expr_type_get(), and use rcu_read_lock() in the caller
nft_expr_type_get() to protect the entire type query process.', 'Use safe libraries to access resources such as files. Be aware that improper use of access function calls such as chown(), tempfile(), chmod(), etc. can cause a race condition. Use synchronization to control the flow of execution. Use static analysis tools to find race conditions. Pay attention to concurrency problems related to the access of resources.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2022-48747', '2024-11-24 09:01:55.235379', 'https://cve.circl.lu/cve/CVE-2022-48747', 'Red Hat Update for kernel (RHSA-2024:5101)', 7.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

block: Fix wrong offset in bio_truncate()

bio_truncate() clears the buffer outside of last block of bdev, however
current bio_truncate() is using the wrong offset of page. So it can
return the uninitialized data.

This happened when both of truncated/corrupted FS and userspace (via
bdev) are trying to read the last of bdev.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47408', '2024-11-24 09:01:55.235380', 'https://cve.circl.lu/cve/CVE-2021-47408', 'Red Hat Update for kernel (RHSA-2024:5101)', 4.7, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

netfilter: conntrack: serialize hash resizes and cleanups

Syzbot was able to trigger the following warning [1]

No repro found by syzbot yet but I was able to trigger similar issue
by having 2 scripts running in parallel, changing conntrack hash sizes,
and:

for j in `seq 1 1000` ; do unshare -n /bin/true >/dev/null ; done

It would take more than 5 minutes for net_namespace structures
to be cleaned up.

This is because nf_ct_iterate_cleanup() has to restart everytime
a resize happened.

By adding a mutex, we can serialize hash resizes and cleanups
and also make get_next_corpse() faster by skipping over empty
buckets.

Even without resizes in the picture, this patch considerably
speeds up network namespace dismantles.

[1]
INFO: task syz-executor.0:8312 can\'t die for more than 144 seconds.
task:syz-executor.0  state:R  running task     stack:25672 pid: 8312 ppid:  6573 flags:0x00004006
Call Trace:
 context_switch kernel/sched/core.c:4955 [inline]
 __schedule+0x940/0x26f0 kernel/sched/core.c:6236
 preempt_schedule_common+0x45/0xc0 kernel/sched/core.c:6408
 preempt_schedule_thunk+0x16/0x18 arch/x86/entry/thunk_64.S:35
 __local_bh_enable_ip+0x109/0x120 kernel/softirq.c:390
 local_bh_enable include/linux/bottom_half.h:32 [inline]
 get_next_corpse net/netfilter/nf_conntrack_core.c:2252 [inline]
 nf_ct_iterate_cleanup+0x15a/0x450 net/netfilter/nf_conntrack_core.c:2275
 nf_conntrack_cleanup_net_list+0x14c/0x4f0 net/netfilter/nf_conntrack_core.c:2469
 ops_exit_list+0x10d/0x160 net/core/net_namespace.c:171
 setup_net+0x639/0xa30 net/core/net_namespace.c:349
 copy_net_ns+0x319/0x760 net/core/net_namespace.c:470
 create_new_namespaces+0x3f6/0xb20 kernel/nsproxy.c:110
 unshare_nsproxy_namespaces+0xc1/0x1f0 kernel/nsproxy.c:226
 ksys_unshare+0x445/0x920 kernel/fork.c:3128
 __do_sys_unshare kernel/fork.c:3202 [inline]
 __se_sys_unshare kernel/fork.c:3200 [inline]
 __x64_sys_unshare+0x2d/0x40 kernel/fork.c:3200
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x44/0xae
RIP: 0033:0x7f63da68e739
RSP: 002b:00007f63d7c05188 EFLAGS: 00000246 ORIG_RAX: 0000000000000110
RAX: ffffffffffffffda RBX: 00007f63da792f80 RCX: 00007f63da68e739
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000040000000
RBP: 00007f63da6e8cc4 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 00007f63da792f80
R13: 00007fff50b75d3f R14: 00007f63d7c05300 R15: 0000000000022000

Showing all locks held in the system:
1 lock held by khungtaskd/27:
 #0: ffffffff8b980020 (rcu_read_lock){....}-{1:2}, at: debug_show_all_locks+0x53/0x260 kernel/locking/lockdep.c:6446
2 locks held by kworker/u4:2/153:
 #0: ffff888010c69138 ((wq_completion)events_unbound){+.+.}-{0:0}, at: arch_atomic64_set arch/x86/include/asm/atomic64_64.h:34 [inline]
 #0: ffff888010c69138 ((wq_completion)events_unbound){+.+.}-{0:0}, at: arch_atomic_long_set include/linux/atomic/atomic-long.h:41 [inline]
 #0: ffff888010c69138 ((wq_completion)events_unbound){+.+.}-{0:0}, at: atomic_long_set include/linux/atomic/atomic-instrumented.h:1198 [inline]
 #0: ffff888010c69138 ((wq_completion)events_unbound){+.+.}-{0:0}, at: set_work_data kernel/workqueue.c:634 [inline]
 #0: ffff888010c69138 ((wq_completion)events_unbound){+.+.}-{0:0}, at: set_work_pool_and_clear_pending kernel/workqueue.c:661 [inline]
 #0: ffff888010c69138 ((wq_completion)events_unbound){+.+.}-{0:0}, at: process_one_work+0x896/0x1690 kernel/workqueue.c:2268
 #1: ffffc9000140fdb0 ((kfence_timer).work){+.+.}-{0:0}, at: process_one_work+0x8ca/0x1690 kernel/workqueue.c:2272
1 lock held by systemd-udevd/2970:
1 lock held by in:imklog/6258:
 #0: ffff88807f970ff0 (&f->f_pos_lock){+.+.}-{3:3}, at: __fdget_pos+0xe9/0x100 fs/file.c:990
3 locks held by kworker/1:6/8158:
1 lock held by syz-executor.0/8312:
2 locks held by kworker/u4:13/9320:
1 lock held by
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47284', '2024-11-24 09:01:55.235381', 'https://cve.circl.lu/cve/CVE-2021-47284', 'Red Hat Update for kernel (RHSA-2024:5101)', 4.7, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

isdn: mISDN: netjet: Fix crash in nj_probe:

\'nj_setup\' in netjet.c might fail with -EIO and in this case
\'card->irq\' is initialized and is bigger than zero. A subsequent call to
\'nj_release\' will free the irq that has not been requested.

Fix this bug by deleting the previous assignment to \'card->irq\' and just
keep the assignment before \'request_irq\'.

The KASAN\'s log reveals it:

[    3.354615 ] WARNING: CPU: 0 PID: 1 at kernel/irq/manage.c:1826
free_irq+0x100/0x480
[    3.355112 ] Modules linked in:
[    3.355310 ] CPU: 0 PID: 1 Comm: swapper/0 Not tainted
5.13.0-rc1-00144-g25a1298726e #13
[    3.355816 ] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
[    3.356552 ] RIP: 0010:free_irq+0x100/0x480
[    3.356820 ] Code: 6e 08 74 6f 4d 89 f4 e8 5e ac 09 00 4d 8b 74 24 18
4d 85 f6 75 e3 e8 4f ac 09 00 8b 75 c8 48 c7 c7 78 c1 2e 85 e8 e0 cf f5
ff <0f> 0b 48 8b 75 c0 4c 89 ff e8 72 33 0b 03 48 8b 43 40 4c 8b a0 80
[    3.358012 ] RSP: 0000:ffffc90000017b48 EFLAGS: 00010082
[    3.358357 ] RAX: 0000000000000000 RBX: ffff888104dc8000 RCX:
0000000000000000
[    3.358814 ] RDX: ffff8881003c8000 RSI: ffffffff8124a9e6 RDI:
00000000ffffffff
[    3.359272 ] RBP: ffffc90000017b88 R08: 0000000000000000 R09:
0000000000000000
[    3.359732 ] R10: ffffc900000179f0 R11: 0000000000001d04 R12:
0000000000000000
[    3.360195 ] R13: ffff888107dc6000 R14: ffff888107dc6928 R15:
ffff888104dc80a8
[    3.360652 ] FS:  0000000000000000(0000) GS:ffff88817bc00000(0000)
knlGS:0000000000000000
[    3.361170 ] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    3.361538 ] CR2: 0000000000000000 CR3: 000000000582e000 CR4:
00000000000006f0
[    3.362003 ] DR0: 0000000000000000 DR1: 0000000000000000 DR2:
0000000000000000
[    3.362175 ] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
0000000000000400
[    3.362175 ] Call Trace:
[    3.362175 ]  nj_release+0x51/0x1e0
[    3.362175 ]  nj_probe+0x450/0x950
[    3.362175 ]  ? pci_device_remove+0x110/0x110
[    3.362175 ]  local_pci_probe+0x45/0xa0
[    3.362175 ]  pci_device_probe+0x12b/0x1d0
[    3.362175 ]  really_probe+0x2a9/0x610
[    3.362175 ]  driver_probe_device+0x90/0x1d0
[    3.362175 ]  ? mutex_lock_nested+0x1b/0x20
[    3.362175 ]  device_driver_attach+0x68/0x70
[    3.362175 ]  __driver_attach+0x124/0x1b0
[    3.362175 ]  ? device_driver_attach+0x70/0x70
[    3.362175 ]  bus_for_each_dev+0xbb/0x110
[    3.362175 ]  ? rdinit_setup+0x45/0x45
[    3.362175 ]  driver_attach+0x27/0x30
[    3.362175 ]  bus_add_driver+0x1eb/0x2a0
[    3.362175 ]  driver_register+0xa9/0x180
[    3.362175 ]  __pci_register_driver+0x82/0x90
[    3.362175 ]  ? w6692_init+0x38/0x38
[    3.362175 ]  nj_init+0x36/0x38
[    3.362175 ]  do_one_initcall+0x7f/0x3d0
[    3.362175 ]  ? rdinit_setup+0x45/0x45
[    3.362175 ]  ? rcu_read_lock_sched_held+0x4f/0x80
[    3.362175 ]  kernel_init_freeable+0x2aa/0x301
[    3.362175 ]  ? rest_init+0x2c0/0x2c0
[    3.362175 ]  kernel_init+0x18/0x190
[    3.362175 ]  ? rest_init+0x2c0/0x2c0
[    3.362175 ]  ? rest_init+0x2c0/0x2c0
[    3.362175 ]  ret_from_fork+0x1f/0x30
[    3.362175 ] Kernel panic - not syncing: panic_on_warn set ...
[    3.362175 ] CPU: 0 PID: 1 Comm: swapper/0 Not tainted
5.13.0-rc1-00144-g25a1298726e #13
[    3.362175 ] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
[    3.362175 ] Call Trace:
[    3.362175 ]  dump_stack+0xba/0xf5
[    3.362175 ]  ? free_irq+0x100/0x480
[    3.362175 ]  panic+0x15a/0x3f2
[    3.362175 ]  ? __warn+0xf2/0x150
[    3.362175 ]  ? free_irq+0x100/0x480
[    3.362175 ]  __warn+0x108/0x150
[    3.362175 ]  ? free_irq+0x100/0x480
[    3.362175 ]  report_bug+0x119/0x1c0
[    3.362175 ]  handle_bug+0x3b/0x80
[    3.362175 ]  exc_invalid_op+0x18/0x70
[    3.362175 ]  asm_exc_invalid_op+0x12/0x20
[    3.362175 ] RIP: 0010:free_irq+0x100
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47257', '2024-11-24 09:01:55.235381', 'https://cve.circl.lu/cve/CVE-2021-47257', 'SUSE Enterprise Linux Security Update for the Linux Kernel (SUSE-SU-2024:3251-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

net: ieee802154: fix null deref in parse dev addr

Fix a logic error that could result in a null deref if the user sets
the mode incorrectly for the given addr type.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-36905', '2024-11-24 09:01:55.235388', 'https://cve.circl.lu/cve/CVE-2024-36905', 'Red Hat Update for kernel (RHSA-2024:5101)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets

TCP_SYN_RECV state is really special, it is only used by
cross-syn connections, mostly used by fuzzers.

In the following crash [1], syzbot managed to trigger a divide
by zero in tcp_rcv_space_adjust()

A socket makes the following state transitions,
without ever calling tcp_init_transfer(),
meaning tcp_init_buffer_space() is also not called.

         TCP_CLOSE
connect()
         TCP_SYN_SENT
         TCP_SYN_RECV
shutdown() -> tcp_shutdown(sk, SEND_SHUTDOWN)
         TCP_FIN_WAIT1

To fix this issue, change tcp_shutdown() to not
perform a TCP_SYN_RECV -> TCP_FIN_WAIT1 transition,
which makes no sense anyway.

When tcp_rcv_state_process() later changes socket state
from TCP_SYN_RECV to TCP_ESTABLISH, then look at
sk->sk_shutdown to finally enter TCP_FIN_WAIT1 state,
and send a FIN packet from a sane socket state.

This means tcp_send_fin() can now be called from BH
context, and must use GFP_ATOMIC allocations.

[1]
divide error: 0000 [#1] PREEMPT SMP KASAN NOPTI
CPU: 1 PID: 5084 Comm: syz-executor358 Not tainted 6.9.0-rc6-syzkaller-00022-g98369dccd2f8 #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 03/27/2024
 RIP: 0010:tcp_rcv_space_adjust+0x2df/0x890 net/ipv4/tcp_input.c:767
Code: e3 04 4c 01 eb 48 8b 44 24 38 0f b6 04 10 84 c0 49 89 d5 0f 85 a5 03 00 00 41 8b 8e c8 09 00 00 89 e8 29 c8 48 0f af c3 31 d2 <48> f7 f1 48 8d 1c 43 49 8d 96 76 08 00 00 48 89 d0 48 c1 e8 03 48
RSP: 0018:ffffc900031ef3f0 EFLAGS: 00010246
RAX: 0c677a10441f8f42 RBX: 000000004fb95e7e RCX: 0000000000000000
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
RBP: 0000000027d4b11f R08: ffffffff89e535a4 R09: 1ffffffff25e6ab7
R10: dffffc0000000000 R11: ffffffff8135e920 R12: ffff88802a9f8d30
R13: dffffc0000000000 R14: ffff88802a9f8d00 R15: 1ffff1100553f2da
FS:  00005555775c0380(0000) GS:ffff8880b9500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007f1155bf2304 CR3: 000000002b9f2000 CR4: 0000000000350ef0
Call Trace:
 <TASK>
  tcp_recvmsg_locked+0x106d/0x25a0 net/ipv4/tcp.c:2513
  tcp_recvmsg+0x25d/0x920 net/ipv4/tcp.c:2578
  inet6_recvmsg+0x16a/0x730 net/ipv6/af_inet6.c:680
  sock_recvmsg_nosec net/socket.c:1046 [inline]
  sock_recvmsg+0x109/0x280 net/socket.c:1068
  ____sys_recvmsg+0x1db/0x470 net/socket.c:2803
  ___sys_recvmsg net/socket.c:2845 [inline]
  do_recvmmsg+0x474/0xae0 net/socket.c:2939
  __sys_recvmmsg net/socket.c:3018 [inline]
  __do_sys_recvmmsg net/socket.c:3041 [inline]
  __se_sys_recvmmsg net/socket.c:3034 [inline]
  __x64_sys_recvmmsg+0x199/0x250 net/socket.c:3034
  do_syscall_x64 arch/x86/entry/common.c:52 [inline]
  do_syscall_64+0xf5/0x240 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7faeb6363db9
Code: 28 00 00 00 75 05 48 83 c4 28 c3 e8 c1 17 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007ffcc1997168 EFLAGS: 00000246 ORIG_RAX: 000000000000012b
RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007faeb6363db9
RDX: 0000000000000001 RSI: 0000000020000bc0 RDI: 0000000000000005
RBP: 0000000000000000 R08: 0000000000000000 R09: 000000000000001c
R10: 0000000000000122 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000000 R14: 0000000000000001 R15: 0000000000000001', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2022-48754', '2024-11-24 09:01:55.235396', 'https://cve.circl.lu/cve/CVE-2022-48754', 'Red Hat Update for kernel (RHSA-2024:7000)', 8.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

phylib: fix potential use-after-free

Commit bafbdd527d56 ("phylib: Add device reset GPIO support") added call
to phy_device_reset(phydev) after the put_device() call in phy_detach().

The comment before the put_device() call says that the phydev might go
away with put_device().

Fix potential use-after-free by calling phy_device_reset() before
put_device().', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26960', '2024-11-24 09:01:55.235382', 'https://cve.circl.lu/cve/CVE-2024-26960', 'Red Hat Update for kernel (RHSA-2024:5101)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

mm: swap: fix race between free_swap_and_cache() and swapoff()

There was previously a theoretical window where swapoff() could run and
teardown a swap_info_struct while a call to free_swap_and_cache() was
running in another thread.  This could cause, amongst other bad
possibilities, swap_page_trans_huge_swapped() (called by
free_swap_and_cache()) to access the freed memory for swap_map.

This is a theoretical problem and I haven\'t been able to provoke it from a
test case.  But there has been agreement based on code review that this is
possible (see link below).

Fix it by using get_swap_device()/put_swap_device(), which will stall
swapoff().  There was an extra check in _swap_info_get() to confirm that
the swap entry was not free.  This isn\'t present in get_swap_device()
because it doesn\'t make sense in general due to the race between getting
the reference and swapoff.  So I\'ve added an equivalent check directly in
free_swap_and_cache().

Details of how to provoke one possible issue (thanks to David Hildenbrand
for deriving this):

--8<-----

__swap_entry_free() might be the last user and result in
"count == SWAP_HAS_CACHE".

swapoff->try_to_unuse() will stop as soon as soon as si->inuse_pages==0.

So the question is: could someone reclaim the folio and turn
si->inuse_pages==0, before we completed swap_page_trans_huge_swapped().

Imagine the following: 2 MiB folio in the swapcache. Only 2 subpages are
still references by swap entries.

Process 1 still references subpage 0 via swap entry.
Process 2 still references subpage 1 via swap entry.

Process 1 quits. Calls free_swap_and_cache().
-> count == SWAP_HAS_CACHE
[then, preempted in the hypervisor etc.]

Process 2 quits. Calls free_swap_and_cache().
-> count == SWAP_HAS_CACHE

Process 2 goes ahead, passes swap_page_trans_huge_swapped(), and calls
__try_to_reclaim_swap().

__try_to_reclaim_swap()->folio_free_swap()->delete_from_swap_cache()->
put_swap_folio()->free_swap_slot()->swapcache_free_entries()->
swap_entry_free()->swap_range_free()->
...
WRITE_ONCE(si->inuse_pages, si->inuse_pages - nr_entries);

What stops swapoff to succeed after process 2 reclaimed the swap cache
but before process1 finished its call to swap_page_trans_huge_swapped()?

--8<-----', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26940', '2024-11-24 09:01:55.235383', 'https://cve.circl.lu/cve/CVE-2024-26940', 'Red Hat Update for kernel (RHSA-2024:5101)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

drm/vmwgfx: Create debugfs ttm_resource_manager entry only if needed

The driver creates /sys/kernel/debug/dri/0/mob_ttm even when the
corresponding ttm_resource_manager is not allocated.
This leads to a crash when trying to read from this file.

Add a check to create mob_ttm, system_mob_ttm, and gmr_ttm debug file
only when the corresponding ttm_resource_manager is allocated.

crash> bt
PID: 3133409  TASK: ffff8fe4834a5000  CPU: 3    COMMAND: "grep"
 #0 [ffffb954506b3b20] machine_kexec at ffffffffb2a6bec3
 #1 [ffffb954506b3b78] __crash_kexec at ffffffffb2bb598a
 #2 [ffffb954506b3c38] crash_kexec at ffffffffb2bb68c1
 #3 [ffffb954506b3c50] oops_end at ffffffffb2a2a9b1
 #4 [ffffb954506b3c70] no_context at ffffffffb2a7e913
 #5 [ffffb954506b3cc8] __bad_area_nosemaphore at ffffffffb2a7ec8c
 #6 [ffffb954506b3d10] do_page_fault at ffffffffb2a7f887
 #7 [ffffb954506b3d40] page_fault at ffffffffb360116e
    [exception RIP: ttm_resource_manager_debug+0x11]
    RIP: ffffffffc04afd11  RSP: ffffb954506b3df0  RFLAGS: 00010246
    RAX: ffff8fe41a6d1200  RBX: 0000000000000000  RCX: 0000000000000940
    RDX: 0000000000000000  RSI: ffffffffc04b4338  RDI: 0000000000000000
    RBP: ffffb954506b3e08   R8: ffff8fee3ffad000   R9: 0000000000000000
    R10: ffff8fe41a76a000  R11: 0000000000000001  R12: 00000000ffffffff
    R13: 0000000000000001  R14: ffff8fe5bb6f3900  R15: ffff8fe41a6d1200
    ORIG_RAX: ffffffffffffffff  CS: 0010  SS: 0018
 #8 [ffffb954506b3e00] ttm_resource_manager_show at ffffffffc04afde7 [ttm]
 #9 [ffffb954506b3e30] seq_read at ffffffffb2d8f9f3
    RIP: 00007f4c4eda8985  RSP: 00007ffdbba9e9f8  RFLAGS: 00000246
    RAX: ffffffffffffffda  RBX: 000000000037e000  RCX: 00007f4c4eda8985
    RDX: 000000000037e000  RSI: 00007f4c41573000  RDI: 0000000000000003
    RBP: 000000000037e000   R8: 0000000000000000   R9: 000000000037fe30
    R10: 0000000000000000  R11: 0000000000000246  R12: 00007f4c41573000
    R13: 0000000000000003  R14: 00007f4c41572010  R15: 0000000000000003
    ORIG_RAX: 0000000000000000  CS: 0033  SS: 002b', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26843', '2024-11-24 09:01:55.235384', 'https://cve.circl.lu/cve/CVE-2024-26843', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 6, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

efi: runtime: Fix potential overflow of soft-reserved region size

md_size will have been narrowed if we have >= 4GB worth of pages in a
soft-reserved region.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26810', '2024-11-24 09:01:55.235384', 'https://cve.circl.lu/cve/CVE-2024-26810', 'Red Hat Update for kernel (RHSA-2024:6206)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

vfio/pci: Lock external INTx masking ops

Mask operations through config space changes to DisINTx may race INTx
configuration changes via ioctl.  Create wrappers that add locking for
paths outside of the core interrupt code.

In particular, irq_type is updated holding igate, therefore testing
is_intx() requires holding igate.  For example clearing DisINTx from
config space can otherwise race changes of the interrupt configuration.

This aligns interfaces which may trigger the INTx eventfd into two
camps, one side serialized by igate and the other only enabled while
INTx is configured.  A subsequent patch introduces synchronization for
the latter flows.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26772', '2024-11-24 09:01:55.235385', 'https://cve.circl.lu/cve/CVE-2024-26772', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6831-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

ext4: avoid allocating blocks from corrupted group in ext4_mb_find_by_goal()

Places the logic for checking if the group\'s block bitmap is corrupt under
the protection of the group lock to avoid allocating blocks from the group
with a corrupted block bitmap.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26614', '2024-11-24 09:01:55.235385', 'https://cve.circl.lu/cve/CVE-2024-26614', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6766-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

tcp: make sure init the accept_queue\'s spinlocks once

When I run syz\'s reproduction C program locally, it causes the following
issue:
pvqspinlock: lock 0xffff9d181cd5c660 has corrupted value 0x0!
WARNING: CPU: 19 PID: 21160 at __pv_queued_spin_unlock_slowpath (kernel/locking/qspinlock_paravirt.h:508)
Hardware name: Red Hat KVM, BIOS 0.5.1 01/01/2011
RIP: 0010:__pv_queued_spin_unlock_slowpath (kernel/locking/qspinlock_paravirt.h:508)
Code: 73 56 3a ff 90 c3 cc cc cc cc 8b 05 bb 1f 48 01 85 c0 74 05 c3 cc cc cc cc 8b 17 48 89 fe 48 c7 c7
30 20 ce 8f e8 ad 56 42 ff <0f> 0b c3 cc cc cc cc 0f 0b 0f 1f 40 00 90 90 90 90 90 90 90 90 90
RSP: 0018:ffffa8d200604cb8 EFLAGS: 00010282
RAX: 0000000000000000 RBX: 0000000000000000 RCX: ffff9d1ef60e0908
RDX: 00000000ffffffd8 RSI: 0000000000000027 RDI: ffff9d1ef60e0900
RBP: ffff9d181cd5c280 R08: 0000000000000000 R09: 00000000ffff7fff
R10: ffffa8d200604b68 R11: ffffffff907dcdc8 R12: 0000000000000000
R13: ffff9d181cd5c660 R14: ffff9d1813a3f330 R15: 0000000000001000
FS:  00007fa110184640(0000) GS:ffff9d1ef60c0000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020000000 CR3: 000000011f65e000 CR4: 00000000000006f0
Call Trace:
<IRQ>
  _raw_spin_unlock (kernel/locking/spinlock.c:186)
  inet_csk_reqsk_queue_add (net/ipv4/inet_connection_sock.c:1321)
  inet_csk_complete_hashdance (net/ipv4/inet_connection_sock.c:1358)
  tcp_check_req (net/ipv4/tcp_minisocks.c:868)
  tcp_v4_rcv (net/ipv4/tcp_ipv4.c:2260)
  ip_protocol_deliver_rcu (net/ipv4/ip_input.c:205)
  ip_local_deliver_finish (net/ipv4/ip_input.c:234)
  __netif_receive_skb_one_core (net/core/dev.c:5529)
  process_backlog (./include/linux/rcupdate.h:779)
  __napi_poll (net/core/dev.c:6533)
  net_rx_action (net/core/dev.c:6604)
  __do_softirq (./arch/x86/include/asm/jump_label.h:27)
  do_softirq (kernel/softirq.c:454 kernel/softirq.c:441)
</IRQ>
<TASK>
  __local_bh_enable_ip (kernel/softirq.c:381)
  __dev_queue_xmit (net/core/dev.c:4374)
  ip_finish_output2 (./include/net/neighbour.h:540 net/ipv4/ip_output.c:235)
  __ip_queue_xmit (net/ipv4/ip_output.c:535)
  __tcp_transmit_skb (net/ipv4/tcp_output.c:1462)
  tcp_rcv_synsent_state_process (net/ipv4/tcp_input.c:6469)
  tcp_rcv_state_process (net/ipv4/tcp_input.c:6657)
  tcp_v4_do_rcv (net/ipv4/tcp_ipv4.c:1929)
  __release_sock (./include/net/sock.h:1121 net/core/sock.c:2968)
  release_sock (net/core/sock.c:3536)
  inet_wait_for_connect (net/ipv4/af_inet.c:609)
  __inet_stream_connect (net/ipv4/af_inet.c:702)
  inet_stream_connect (net/ipv4/af_inet.c:748)
  __sys_connect (./include/linux/file.h:45 net/socket.c:2064)
  __x64_sys_connect (net/socket.c:2073 net/socket.c:2070 net/socket.c:2070)
  do_syscall_64 (arch/x86/entry/common.c:51 arch/x86/entry/common.c:82)
  entry_SYSCALL_64_after_hwframe (arch/x86/entry/entry_64.S:129)
  RIP: 0033:0x7fa10ff05a3d
  Code: 5b 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89
  c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d ab a3 0e 00 f7 d8 64 89 01 48
  RSP: 002b:00007fa110183de8 EFLAGS: 00000202 ORIG_RAX: 000000000000002a
  RAX: ffffffffffffffda RBX: 0000000020000054 RCX: 00007fa10ff05a3d
  RDX: 000000000000001c RSI: 0000000020000040 RDI: 0000000000000003
  RBP: 00007fa110183e20 R08: 0000000000000000 R09: 0000000000000000
  R10: 0000000000000000 R11: 0000000000000202 R12: 00007fa110184640
  R13: 0000000000000000 R14: 00007fa10fe8b060 R15: 00007fff73e23b20
</TASK>

The issue triggering process is analyzed as follows:
Thread A                                       Thread B
tcp_v4_rcv	//receive ack TCP packet       inet_shutdown
  tcp_check_req                                  tcp_disconnect //disconnect sock
  ...                                              tcp_set_state(sk, TCP_CLOSE)
    inet_csk_complete_hashdance                ...
      inet_csk_reqsk_queue_add         
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-39276', '2024-11-24 09:01:55.235386', 'https://cve.circl.lu/cve/CVE-2024-39276', 'Red Hat Update for kernel (RHSA-2024:5101)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

ext4: fix mb_cache_entry\'s e_refcnt leak in ext4_xattr_block_cache_find()

Syzbot reports a warning as follows:

============================================
WARNING: CPU: 0 PID: 5075 at fs/mbcache.c:419 mb_cache_destroy+0x224/0x290
Modules linked in:
CPU: 0 PID: 5075 Comm: syz-executor199 Not tainted 6.9.0-rc6-gb947cc5bf6d7
RIP: 0010:mb_cache_destroy+0x224/0x290 fs/mbcache.c:419
Call Trace:
 <TASK>
 ext4_put_super+0x6d4/0xcd0 fs/ext4/super.c:1375
 generic_shutdown_super+0x136/0x2d0 fs/super.c:641
 kill_block_super+0x44/0x90 fs/super.c:1675
 ext4_kill_sb+0x68/0xa0 fs/ext4/super.c:7327
[...]
============================================

This is because when finding an entry in ext4_xattr_block_cache_find(), if
ext4_sb_bread() returns -ENOMEM, the ce\'s e_refcnt, which has already grown
in the __entry_find(), won\'t be put away, and eventually trigger the above
issue in mb_cache_destroy() due to reference count leakage.

So call mb_cache_entry_put() on the -ENOMEM error branch as a quick fix.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38573', '2024-11-24 09:01:55.235387', 'https://cve.circl.lu/cve/CVE-2024-38573', 'Red Hat Update for kernel (RHSA-2024:6997)', 7.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

cppc_cpufreq: Fix possible null pointer dereference

cppc_cpufreq_get_rate() and hisi_cppc_cpufreq_get_rate() can be called from
different places with various parameters. So cpufreq_cpu_get() can return
null as \'policy\' in some circumstances.
Fix this bug by adding null return check.

Found by Linux Verification Center (linuxtesting.org) with SVACE.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52832', '2024-11-24 09:01:55.235387', 'https://cve.circl.lu/cve/CVE-2023-52832', 'Red Hat Update for kernel (RHSA-2024:5101)', 9.1, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

wifi: mac80211: don\'t return unset power in ieee80211_get_tx_power()

We can get a UBSAN warning if ieee80211_get_tx_power() returns the
INT_MIN value mac80211 internally uses for "unset power level".

 UBSAN: signed-integer-overflow in net/wireless/nl80211.c:3816:5
 -2147483648 * 100 cannot be represented in type \'int\'
 CPU: 0 PID: 20433 Comm: insmod Tainted: G        WC OE
 Call Trace:
  dump_stack+0x74/0x92
  ubsan_epilogue+0x9/0x50
  handle_overflow+0x8d/0xd0
  __ubsan_handle_mul_overflow+0xe/0x10
  nl80211_send_iface+0x688/0x6b0 [cfg80211]
  [...]
  cfg80211_register_wdev+0x78/0xb0 [cfg80211]
  cfg80211_netdev_notifier_call+0x200/0x620 [cfg80211]
  [...]
  ieee80211_if_add+0x60e/0x8f0 [mac80211]
  ieee80211_register_hw+0xda5/0x1170 [mac80211]

In this case, simply return an error instead, to indicate
that no data is available.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-36896', '2024-11-24 09:01:55.235389', 'https://cve.circl.lu/cve/CVE-2024-36896', 'Red Hat Update for kernel (RHSA-2024:5101)', 9.1, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

USB: core: Fix access violation during port device removal

Testing with KASAN and syzkaller revealed a bug in port.c:disable_store():
usb_hub_to_struct_hub() can return NULL if the hub that the port belongs to
is concurrently removed, but the function does not check for this
possibility before dereferencing the returned value.

It turns out that the first dereference is unnecessary, since hub->intfdev
is the parent of the port device, so it can be changed easily.  Adding a
check for hub == NULL prevents further problems.

The same bug exists in the disable_show() routine, and it can be fixed the
same way.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-36016', '2024-11-24 09:01:55.235390', 'https://cve.circl.lu/cve/CVE-2024-36016', 'Red Hat Update for kernel (RHSA-2024:6997)', 7.7, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

tty: n_gsm: fix possible out-of-bounds in gsm0_receive()

Assuming the following:
- side A configures the n_gsm in basic option mode
- side B sends the header of a basic option mode frame with data length 1
- side A switches to advanced option mode
- side B sends 2 data bytes which exceeds gsm->len
  Reason: gsm->len is not used in advanced option mode.
- side A switches to basic option mode
- side B keeps sending until gsm0_receive() writes past gsm->buf
  Reason: Neither gsm->state nor gsm->len have been reset after
  reconfiguration.

Fix this by changing gsm->count to gsm->len comparison from equal to less
than. Also add upper limit checks against the constant MAX_MRU in
gsm0_receive() and gsm1_receive() to harden against memory corruption of
gsm->len and gsm->mru.

All other checks remain as we still need to limit the data according to the
user configuration and actual payload size.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35947', '2024-11-24 09:01:55.235390', 'https://cve.circl.lu/cve/CVE-2024-35947', 'Red Hat Update for kernel (RHSA-2024:5101)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

dyndbg: fix old BUG_ON in >control parser

Fix a BUG_ON from 2009.  Even if it looks "unreachable" (I didn\'t
really look), lets make sure by removing it, doing pr_err and return
-EINVAL instead.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26828', '2024-11-24 09:01:55.235391', 'https://cve.circl.lu/cve/CVE-2024-26828', 'Red Hat Update for kernel (RHSA-2024:5363)', 6.7, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

cifs: fix underflow in parse_server_interfaces()

In this loop, we step through the buffer and after each item we check
if the size_left is greater than the minimum size we need.  However,
the problem is that "bytes_left" is type ssize_t while sizeof() is type
size_t.  That means that because of type promotion, the comparison is
done as an unsigned and if we have negative bytes left the loop
continues instead of ending.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35969', '2024-11-24 09:01:55.235392', 'https://cve.circl.lu/cve/CVE-2024-35969', 'Red Hat Update for kernel (RHSA-2024:6993)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

ipv6: fix race condition between ipv6_get_ifaddr and ipv6_del_addr

Although ipv6_get_ifaddr walks inet6_addr_lst under the RCU lock, it
still means hlist_for_each_entry_rcu can return an item that got removed
from the list. The memory itself of such item is not freed thanks to RCU
but nothing guarantees the actual content of the memory is sane.

In particular, the reference count can be zero. This can happen if
ipv6_del_addr is called in parallel. ipv6_del_addr removes the entry
from inet6_addr_lst (hlist_del_init_rcu(&ifp->addr_lst)) and drops all
references (__in6_ifa_put(ifp) + in6_ifa_put(ifp)). With bad enough
timing, this can happen:

1. In ipv6_get_ifaddr, hlist_for_each_entry_rcu returns an entry.

2. Then, the whole ipv6_del_addr is executed for the given entry. The
   reference count drops to zero and kfree_rcu is scheduled.

3. ipv6_get_ifaddr continues and tries to increments the reference count
   (in6_ifa_hold).

4. The rcu is unlocked and the entry is freed.

5. The freed entry is returned.

Prevent increasing of the reference count in such case. The name
in6_ifa_hold_safe is chosen to mimic the existing fib6_info_hold_safe.

[   41.506330] refcount_t: addition on 0; use-after-free.
[   41.506760] WARNING: CPU: 0 PID: 595 at lib/refcount.c:25 refcount_warn_saturate+0xa5/0x130
[   41.507413] Modules linked in: veth bridge stp llc
[   41.507821] CPU: 0 PID: 595 Comm: python3 Not tainted 6.9.0-rc2.main-00208-g49563be82afa #14
[   41.508479] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996)
[   41.509163] RIP: 0010:refcount_warn_saturate+0xa5/0x130
[   41.509586] Code: ad ff 90 0f 0b 90 90 c3 cc cc cc cc 80 3d c0 30 ad 01 00 75 a0 c6 05 b7 30 ad 01 01 90 48 c7 c7 38 cc 7a 8c e8 cc 18 ad ff 90 <0f> 0b 90 90 c3 cc cc cc cc 80 3d 98 30 ad 01 00 0f 85 75 ff ff ff
[   41.510956] RSP: 0018:ffffbda3c026baf0 EFLAGS: 00010282
[   41.511368] RAX: 0000000000000000 RBX: ffff9e9c46914800 RCX: 0000000000000000
[   41.511910] RDX: ffff9e9c7ec29c00 RSI: ffff9e9c7ec1c900 RDI: ffff9e9c7ec1c900
[   41.512445] RBP: ffff9e9c43660c9c R08: 0000000000009ffb R09: 00000000ffffdfff
[   41.512998] R10: 00000000ffffdfff R11: ffffffff8ca58a40 R12: ffff9e9c4339a000
[   41.513534] R13: 0000000000000001 R14: ffff9e9c438a0000 R15: ffffbda3c026bb48
[   41.514086] FS:  00007fbc4cda1740(0000) GS:ffff9e9c7ec00000(0000) knlGS:0000000000000000
[   41.514726] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   41.515176] CR2: 000056233b337d88 CR3: 000000000376e006 CR4: 0000000000370ef0
[   41.515713] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[   41.516252] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[   41.516799] Call Trace:
[   41.517037]  <TASK>
[   41.517249]  ? __warn+0x7b/0x120
[   41.517535]  ? refcount_warn_saturate+0xa5/0x130
[   41.517923]  ? report_bug+0x164/0x190
[   41.518240]  ? handle_bug+0x3d/0x70
[   41.518541]  ? exc_invalid_op+0x17/0x70
[   41.520972]  ? asm_exc_invalid_op+0x1a/0x20
[   41.521325]  ? refcount_warn_saturate+0xa5/0x130
[   41.521708]  ipv6_get_ifaddr+0xda/0xe0
[   41.522035]  inet6_rtm_getaddr+0x342/0x3f0
[   41.522376]  ? __pfx_inet6_rtm_getaddr+0x10/0x10
[   41.522758]  rtnetlink_rcv_msg+0x334/0x3d0
[   41.523102]  ? netlink_unicast+0x30f/0x390
[   41.523445]  ? __pfx_rtnetlink_rcv_msg+0x10/0x10
[   41.523832]  netlink_rcv_skb+0x53/0x100
[   41.524157]  netlink_unicast+0x23b/0x390
[   41.524484]  netlink_sendmsg+0x1f2/0x440
[   41.524826]  __sys_sendto+0x1d8/0x1f0
[   41.525145]  __x64_sys_sendto+0x1f/0x30
[   41.525467]  do_syscall_64+0xa5/0x1b0
[   41.525794]  entry_SYSCALL_64_after_hwframe+0x72/0x7a
[   41.526213] RIP: 0033:0x7fbc4cfcea9a
[   41.526528] Code: d8 64 89 02 48 c7 c0 ff ff ff ff eb b8 0f 1f 00 f3 0f 1e fa 41 89 ca 64 8b 04 25 18 00 00 00 85 c0 75 15 b8 2c 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 7e c3 0f 1f 44 00 00 41 54 48 83 ec 30 44 89
[   41.527942] RSP: 002b:00007f
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38544', '2024-11-24 09:01:55.235392', 'https://cve.circl.lu/cve/CVE-2024-38544', 'Red Hat Update for kernel (RHSA-2024:5928)', 6.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

RDMA/rxe: Fix seg fault in rxe_comp_queue_pkt

In rxe_comp_queue_pkt() an incoming response packet skb is enqueued to the
resp_pkts queue and then a decision is made whether to run the completer
task inline or schedule it. Finally the skb is dereferenced to bump a \'hw\'
performance counter. This is wrong because if the completer task is
already running in a separate thread it may have already processed the skb
and freed it which can cause a seg fault.  This has been observed
infrequently in testing at high scale.

This patch fixes this by changing the order of enqueuing the packet until
after the counter is accessed.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38540', '2024-11-24 09:01:55.235393', 'https://cve.circl.lu/cve/CVE-2024-38540', 'Red Hat Update for kernel (RHSA-2024:6206)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

bnxt_re: avoid shift undefined behavior in bnxt_qplib_alloc_init_hwq

Undefined behavior is triggered when bnxt_qplib_alloc_init_hwq is called
with hwq_attr->aux_depth != 0 and hwq_attr->aux_stride == 0.
In that case, "roundup_pow_of_two(hwq_attr->aux_stride)" gets called.
roundup_pow_of_two is documented as undefined for 0.

Fix it in the one caller that had this combination.

The undefined behavior was detected by UBSAN:
  UBSAN: shift-out-of-bounds in ./include/linux/log2.h:57:13
  shift exponent 64 is too large for 64-bit type \'long unsigned int\'
  CPU: 24 PID: 1075 Comm: (udev-worker) Not tainted 6.9.0-rc6+ #4
  Hardware name: Abacus electric, s.r.o. - servis@abacus.cz Super Server/H12SSW-iN, BIOS 2.7 10/25/2023
  Call Trace:
   <TASK>
   dump_stack_lvl+0x5d/0x80
   ubsan_epilogue+0x5/0x30
   __ubsan_handle_shift_out_of_bounds.cold+0x61/0xec
   __roundup_pow_of_two+0x25/0x35 [bnxt_re]
   bnxt_qplib_alloc_init_hwq+0xa1/0x470 [bnxt_re]
   bnxt_qplib_create_qp+0x19e/0x840 [bnxt_re]
   bnxt_re_create_qp+0x9b1/0xcd0 [bnxt_re]
   ? srso_alias_return_thunk+0x5/0xfbef5
   ? srso_alias_return_thunk+0x5/0xfbef5
   ? __kmalloc+0x1b6/0x4f0
   ? create_qp.part.0+0x128/0x1c0 [ib_core]
   ? __pfx_bnxt_re_create_qp+0x10/0x10 [bnxt_re]
   create_qp.part.0+0x128/0x1c0 [ib_core]
   ib_create_qp_kernel+0x50/0xd0 [ib_core]
   create_mad_qp+0x8e/0xe0 [ib_core]
   ? __pfx_qp_event_handler+0x10/0x10 [ib_core]
   ib_mad_init_device+0x2be/0x680 [ib_core]
   add_client_context+0x10d/0x1a0 [ib_core]
   enable_device_and_get+0xe0/0x1d0 [ib_core]
   ib_register_device+0x53c/0x630 [ib_core]
   ? srso_alias_return_thunk+0x5/0xfbef5
   bnxt_re_probe+0xbd8/0xe50 [bnxt_re]
   ? __pfx_bnxt_re_probe+0x10/0x10 [bnxt_re]
   auxiliary_bus_probe+0x49/0x80
   ? driver_sysfs_add+0x57/0xc0
   really_probe+0xde/0x340
   ? pm_runtime_barrier+0x54/0x90
   ? __pfx___driver_attach+0x10/0x10
   __driver_probe_device+0x78/0x110
   driver_probe_device+0x1f/0xa0
   __driver_attach+0xba/0x1c0
   bus_for_each_dev+0x8f/0xe0
   bus_add_driver+0x146/0x220
   driver_register+0x72/0xd0
   __auxiliary_driver_register+0x6e/0xd0
   ? __pfx_bnxt_re_mod_init+0x10/0x10 [bnxt_re]
   bnxt_re_mod_init+0x3e/0xff0 [bnxt_re]
   ? __pfx_bnxt_re_mod_init+0x10/0x10 [bnxt_re]
   do_one_initcall+0x5b/0x310
   do_init_module+0x90/0x250
   init_module_from_file+0x86/0xc0
   idempotent_init_module+0x121/0x2b0
   __x64_sys_finit_module+0x5e/0xb0
   do_syscall_64+0x82/0x160
   ? srso_alias_return_thunk+0x5/0xfbef5
   ? syscall_exit_to_user_mode_prepare+0x149/0x170
   ? srso_alias_return_thunk+0x5/0xfbef5
   ? syscall_exit_to_user_mode+0x75/0x230
   ? srso_alias_return_thunk+0x5/0xfbef5
   ? do_syscall_64+0x8e/0x160
   ? srso_alias_return_thunk+0x5/0xfbef5
   ? __count_memcg_events+0x69/0x100
   ? srso_alias_return_thunk+0x5/0xfbef5
   ? count_memcg_events.constprop.0+0x1a/0x30
   ? srso_alias_return_thunk+0x5/0xfbef5
   ? handle_mm_fault+0x1f0/0x300
   ? srso_alias_return_thunk+0x5/0xfbef5
   ? do_user_addr_fault+0x34e/0x640
   ? srso_alias_return_thunk+0x5/0xfbef5
   ? srso_alias_return_thunk+0x5/0xfbef5
   entry_SYSCALL_64_after_hwframe+0x76/0x7e
  RIP: 0033:0x7f4e5132821d
  Code: ff c3 66 2e 0f 1f 84 00 00 00 00 00 90 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d e3 db 0c 00 f7 d8 64 89 01 48
  RSP: 002b:00007ffca9c906a8 EFLAGS: 00000246 ORIG_RAX: 0000000000000139
  RAX: ffffffffffffffda RBX: 0000563ec8a8f130 RCX: 00007f4e5132821d
  RDX: 0000000000000000 RSI: 00007f4e518fa07d RDI: 000000000000003b
  RBP: 00007ffca9c90760 R08: 00007f4e513f6b20 R09: 00007ffca9c906f0
  R10: 0000563ec8a8faa0 R11: 0000000000000246 R12: 00007f4e518fa07d
  R13: 0000000000020000 R14: 0000563ec8409e90 R15: 0000563ec8a8fa60
   </TASK>
  ---[ end trace ]---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35898', '2024-11-24 09:01:55.235394', 'https://cve.circl.lu/cve/CVE-2024-35898', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get()

nft_unregister_flowtable_type() within nf_flow_inet_module_exit() can
concurrent with __nft_flowtable_type_get() within nf_tables_newflowtable().
And thhere is not any protection when iterate over nf_tables_flowtables
list in __nft_flowtable_type_get(). Therefore, there is pertential
data-race of nf_tables_flowtables list entry.

Use list_for_each_entry_rcu() to iterate over nf_tables_flowtables list
in __nft_flowtable_type_get(), and use rcu_read_lock() in the caller
nft_flowtable_type_get() to protect the entire type query process.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26581', '2024-11-24 09:01:55.235394', 'https://cve.circl.lu/cve/CVE-2024-26581', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6742-1)', 7.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

netfilter: nft_set_rbtree: skip end interval element from gc

rbtree lazy gc on insert might collect an end interval element that has
been just added in this transactions, skip end interval elements that
are not yet active.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52771', '2024-11-24 09:01:55.235395', 'https://cve.circl.lu/cve/CVE-2023-52771', 'Red Hat Update for kernel (RHSA-2024:5928)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

cxl/port: Fix delete_endpoint() vs parent unregistration race

The CXL subsystem, at cxl_mem ->probe() time, establishes a lineage of
ports (struct cxl_port objects) between an endpoint and the root of a
CXL topology. Each port including the endpoint port is attached to the
cxl_port driver.

Given that setup, it follows that when either any port in that lineage
goes through a cxl_port ->remove() event, or the memdev goes through a
cxl_mem ->remove() event. The hierarchy below the removed port, or the
entire hierarchy if the memdev is removed needs to come down.

The delete_endpoint() callback is careful to check whether it is being
called to tear down the hierarchy, or if it is only being called to
teardown the memdev because an ancestor port is going through
->remove().

That care needs to take the device_lock() of the endpoint\'s parent.
Which requires 2 bugs to be fixed:

1/ A reference on the parent is needed to prevent use-after-free
   scenarios like this signature:

    BUG: spinlock bad magic on CPU#0, kworker/u56:0/11
    Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS edk2-20230524-3.fc38 05/24/2023
    Workqueue: cxl_port detach_memdev [cxl_core]
    RIP: 0010:spin_bug+0x65/0xa0
    Call Trace:
      do_raw_spin_lock+0x69/0xa0
     __mutex_lock+0x695/0xb80
     delete_endpoint+0xad/0x150 [cxl_core]
     devres_release_all+0xb8/0x110
     device_unbind_cleanup+0xe/0x70
     device_release_driver_internal+0x1d2/0x210
     detach_memdev+0x15/0x20 [cxl_core]
     process_one_work+0x1e3/0x4c0
     worker_thread+0x1dd/0x3d0

2/ In the case of RCH topologies, the parent device that needs to be
   locked is not always @port->dev as returned by cxl_mem_find_port(), use
   endpoint->dev.parent instead.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52883', '2024-11-24 09:01:55.235395', 'https://cve.circl.lu/cve/CVE-2023-52883', 'Red Hat Update for kernel (RHSA-2024:6206)', 7.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

drm/amdgpu: Fix possible null pointer dereference

abo->tbo.resource may be NULL in amdgpu_vm_bo_update.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38559', '2024-11-24 09:01:55.235397', 'https://cve.circl.lu/cve/CVE-2024-38559', 'Red Hat Update for kernel (RHSA-2024:7000)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

scsi: qedf: Ensure the copied buf is NUL terminated

Currently, we allocate a count-sized kernel buffer and copy count from
userspace to that buffer. Later, we use kstrtouint on this buffer but we
don\'t ensure that the string is terminated inside the buffer, this can
lead to OOB read when using kstrtouint. Fix this issue by using
memdup_user_nul instead of memdup_user.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35797', '2024-11-24 09:01:55.235398', 'https://cve.circl.lu/cve/CVE-2024-35797', 'Red Hat Update for kernel (RHSA-2024:6567)', 5.3, 'Medium', e'In the Linux kernel, the following vulnerability has been resolved:

mm: cachestat: fix two shmem bugs

When cachestat on shmem races with swapping and invalidation, there
are two possible bugs:

1) A swapin error can have resulted in a poisoned swap entry in the
   shmem inode\'s xarray. Calling get_shadow_from_swap_cache() on it
   will result in an out-of-bounds access to swapper_spaces[].

   Validate the entry with non_swap_entry() before going further.

2) When we find a valid swap entry in the shmem\'s inode, the shadow
   entry in the swapcache might not exist yet: swap IO is still in
   progress and we\'re before __remove_mapping; swapin, invalidation,
   or swapoff have removed the shadow from swapcache after we saw the
   shmem swap entry.

   This will send a NULL to workingset_test_recent(). The latter
   purely operates on pointer bits, so it won\'t crash - node 0, memcg
   ID 0, eviction timestamp 0, etc. are all valid inputs - but it\'s a
   bogus test. In theory that could result in a false "recently
   evicted" count.

   Such a false positive wouldn\'t be the end of the world. But for
   code clarity and (future) robustness, be explicit about this case.

   Bail on get_shadow_from_swap_cache() returning NULL.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52801', '2024-11-24 09:01:55.235398', 'https://cve.circl.lu/cve/CVE-2023-52801', 'Red Hat Update for kernel (RHSA-2024:6567)', 9.1, 'Medium', e'In the Linux kernel, the following vulnerability has been resolved:

iommufd: Fix missing update of domains_itree after splitting iopt_area

In iopt_area_split(), if the original iopt_area has filled a domain and is
linked to domains_itree, pages_nodes have to be properly
reinserted. Otherwise the domains_itree becomes corrupted and we will UAF.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52522', '2024-11-24 09:01:55.235399', 'https://cve.circl.lu/cve/CVE-2023-52522', 'Red Hat Update for kernel (RHSA-2024:7000)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

net: fix possible store tearing in neigh_periodic_work()

While looking at a related syzbot report involving neigh_periodic_work(),
I found that I forgot to add an annotation when deleting an
RCU protected item from a list.

Readers use rcu_deference(*np), we need to use either
rcu_assign_pointer() or WRITE_ONCE() on writer side
to prevent store tearing.

I use rcu_assign_pointer() to have lockdep support,
this was the choice made in neigh_flush_dev().', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2022-48638', '2024-11-24 09:01:55.235400', 'https://cve.circl.lu/cve/CVE-2022-48638', 'Red Hat Update for kernel (RHSA-2024:6993)', 5.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

cgroup: cgroup_get_from_id() must check the looked-up kn is a directory

cgroup has to be one kernfs dir, otherwise kernel panic is caused,
especially cgroup id is provide from userspace.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47384', '2024-11-24 09:01:55.235400', 'https://cve.circl.lu/cve/CVE-2021-47384', 'Red Hat Update for kernel (RHSA-2024:7000)', 5.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

hwmon: (w83793) Fix NULL pointer dereference by removing unnecessary structure field

If driver read tmp value sufficient for
(tmp & 0x08) && (!(tmp & 0x80)) && ((tmp & 0x7) == ((tmp >> 4) & 0x7))
from device then Null pointer dereference occurs.
(It is possible if tmp = 0b0xyz1xyz, where same literals mean same numbers)
Also lm75[] does not serve a purpose anymore after switching to
devm_i2c_new_dummy_device() in w83791d_detect_subclients().

The patch fixes possible NULL pointer dereference by removing lm75[].

Found by Linux Driver Verification project (linuxtesting.org).

[groeck: Dropped unnecessary continuation lines, fixed multi-line alignments]', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38562', '2024-11-24 09:01:55.235401', 'https://cve.circl.lu/cve/CVE-2024-38562', 'Red Hat Update for kernel (RHSA-2024:6997)', 7.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

wifi: nl80211: Avoid address calculations via out of bounds array indexing

Before request->channels[] can be used, request->n_channels must be set.
Additionally, address calculations for memory after the "channels" array
need to be calculated from the allocation base ("request") rather than
via the first "out of bounds" index of "channels", otherwise run-time
bounds checking will throw a warning.', 'Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26991', '2024-11-24 09:01:55.235401', 'https://cve.circl.lu/cve/CVE-2024-26991', 'Red Hat Update for kernel (RHSA-2024:6997)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

KVM: x86/mmu: x86: Don\'t overflow lpage_info when checking attributes

Fix KVM_SET_MEMORY_ATTRIBUTES to not overflow lpage_info array and trigger
KASAN splat, as seen in the private_mem_conversions_test selftest.

When memory attributes are set on a GFN range, that range will have
specific properties applied to the TDP. A huge page cannot be used when
the attributes are inconsistent, so they are disabled for those the
specific huge pages. For internal KVM reasons, huge pages are also not
allowed to span adjacent memslots regardless of whether the backing memory
could be mapped as huge.

What GFNs support which huge page sizes is tracked by an array of arrays
\'lpage_info\' on the memslot, of ‘kvm_lpage_info’ structs. Each index of
lpage_info contains a vmalloc allocated array of these for a specific
supported page size. The kvm_lpage_info denotes whether a specific huge
page (GFN and page size) on the memslot is supported. These arrays include
indices for unaligned head and tail huge pages.

Preventing huge pages from spanning adjacent memslot is covered by
incrementing the count in head and tail kvm_lpage_info when the memslot is
allocated, but disallowing huge pages for memory that has mixed attributes
has to be done in a more complicated way. During the
KVM_SET_MEMORY_ATTRIBUTES ioctl KVM updates lpage_info for each memslot in
the range that has mismatched attributes. KVM does this a memslot at a
time, and marks a special bit, KVM_LPAGE_MIXED_FLAG, in the kvm_lpage_info
for any huge page. This bit is essentially a permanently elevated count.
So huge pages will not be mapped for the GFN at that page size if the
count is elevated in either case: a huge head or tail page unaligned to
the memslot or if KVM_LPAGE_MIXED_FLAG is set because it has mixed
attributes.

To determine whether a huge page has consistent attributes, the
KVM_SET_MEMORY_ATTRIBUTES operation checks an xarray to make sure it
consistently has the incoming attribute. Since level - 1 huge pages are
aligned to level huge pages, it employs an optimization. As long as the
level - 1 huge pages are checked first, it can just check these and assume
that if each level - 1 huge page contained within the level sized huge
page is not mixed, then the level size huge page is not mixed. This
optimization happens in the helper hugepage_has_attrs().

Unfortunately, although the kvm_lpage_info array representing page size
\'level\' will contain an entry for an unaligned tail page of size level,
the array for level - 1  will not contain an entry for each GFN at page
size level. The level - 1 array will only contain an index for any
unaligned region covered by level - 1 huge page size, which can be a
smaller region. So this causes the optimization to overflow the level - 1
kvm_lpage_info and perform a vmalloc out of bounds read.

In some cases of head and tail pages where an overflow could happen,
callers skip the operation completely as KVM_LPAGE_MIXED_FLAG is not
required to prevent huge pages as discussed earlier. But for memslots that
are smaller than the 1GB page size, it does call hugepage_has_attrs(). In
this case the huge page is both the head and tail page. The issue can be
observed simply by compiling the kernel with CONFIG_KASAN_VMALLOC and
running the selftest “private_mem_conversions_test”, which produces the
output like the following:

BUG: KASAN: vmalloc-out-of-bounds in hugepage_has_attrs+0x7e/0x110
Read of size 4 at addr ffffc900000a3008 by task private_mem_con/169
Call Trace:
  dump_stack_lvl
  print_report
  ? __virt_addr_valid
  ? hugepage_has_attrs
  ? hugepage_has_attrs
  kasan_report
  ? hugepage_has_attrs
  hugepage_has_attrs
  kvm_arch_post_set_memory_attributes
  kvm_vm_ioctl

It is a little ambiguous whether the unaligned head page (in the bug case
also the tail page) should be expected to have KVM_LPAGE_MIXED_FLAG set.
It is not functionally required, as the unal
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52884', '2024-11-24 09:01:55.235402', 'https://cve.circl.lu/cve/CVE-2023-52884', 'Red Hat Update for kernel (RHSA-2024:6997)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

Input: cyapa - add missing input core locking to suspend/resume functions

Grab input->mutex during suspend/resume functions like it is done in
other input drivers. This fixes the following warning during system
suspend/resume cycle on Samsung Exynos5250-based Snow Chromebook:

------------[ cut here ]------------
WARNING: CPU: 1 PID: 1680 at drivers/input/input.c:2291 input_device_enabled+0x68/0x6c
Modules linked in: ...
CPU: 1 PID: 1680 Comm: kworker/u4:12 Tainted: G        W          6.6.0-rc5-next-20231009 #14109
Hardware name: Samsung Exynos (Flattened Device Tree)
Workqueue: events_unbound async_run_entry_fn
 unwind_backtrace from show_stack+0x10/0x14
 show_stack from dump_stack_lvl+0x58/0x70
 dump_stack_lvl from __warn+0x1a8/0x1cc
 __warn from warn_slowpath_fmt+0x18c/0x1b4
 warn_slowpath_fmt from input_device_enabled+0x68/0x6c
 input_device_enabled from cyapa_gen3_set_power_mode+0x13c/0x1dc
 cyapa_gen3_set_power_mode from cyapa_reinitialize+0x10c/0x15c
 cyapa_reinitialize from cyapa_resume+0x48/0x98
 cyapa_resume from dpm_run_callback+0x90/0x298
 dpm_run_callback from device_resume+0xb4/0x258
 device_resume from async_resume+0x20/0x64
 async_resume from async_run_entry_fn+0x40/0x15c
 async_run_entry_fn from process_scheduled_works+0xbc/0x6a8
 process_scheduled_works from worker_thread+0x188/0x454
 worker_thread from kthread+0x108/0x140
 kthread from ret_from_fork+0x14/0x28
Exception stack(0xf1625fb0 to 0xf1625ff8)
...
---[ end trace 0000000000000000 ]---
...
------------[ cut here ]------------
WARNING: CPU: 1 PID: 1680 at drivers/input/input.c:2291 input_device_enabled+0x68/0x6c
Modules linked in: ...
CPU: 1 PID: 1680 Comm: kworker/u4:12 Tainted: G        W          6.6.0-rc5-next-20231009 #14109
Hardware name: Samsung Exynos (Flattened Device Tree)
Workqueue: events_unbound async_run_entry_fn
 unwind_backtrace from show_stack+0x10/0x14
 show_stack from dump_stack_lvl+0x58/0x70
 dump_stack_lvl from __warn+0x1a8/0x1cc
 __warn from warn_slowpath_fmt+0x18c/0x1b4
 warn_slowpath_fmt from input_device_enabled+0x68/0x6c
 input_device_enabled from cyapa_gen3_set_power_mode+0x13c/0x1dc
 cyapa_gen3_set_power_mode from cyapa_reinitialize+0x10c/0x15c
 cyapa_reinitialize from cyapa_resume+0x48/0x98
 cyapa_resume from dpm_run_callback+0x90/0x298
 dpm_run_callback from device_resume+0xb4/0x258
 device_resume from async_resume+0x20/0x64
 async_resume from async_run_entry_fn+0x40/0x15c
 async_run_entry_fn from process_scheduled_works+0xbc/0x6a8
 process_scheduled_works from worker_thread+0x188/0x454
 worker_thread from kthread+0x108/0x140
 kthread from ret_from_fork+0x14/0x28
Exception stack(0xf1625fb0 to 0xf1625ff8)
...
---[ end trace 0000000000000000 ]---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26769', '2024-11-24 09:01:55.235403', 'https://cve.circl.lu/cve/CVE-2024-26769', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

nvmet-fc: avoid deadlock on delete association path

When deleting an association the shutdown path is deadlocking because we
try to flush the nvmet_wq nested. Avoid this by deadlock by deferring
the put work into its own work item.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47441', '2024-11-24 09:01:55.235403', 'https://cve.circl.lu/cve/CVE-2021-47441', 'Red Hat Update for kernel (RHSA-2024:7000)', 7.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

mlxsw: thermal: Fix out-of-bounds memory accesses

Currently, mlxsw allows cooling states to be set above the maximum
cooling state supported by the driver:

 # cat /sys/class/thermal/thermal_zone2/cdev0/type
 mlxsw_fan
 # cat /sys/class/thermal/thermal_zone2/cdev0/max_state
 10
 # echo 18 > /sys/class/thermal/thermal_zone2/cdev0/cur_state
 # echo $?
 0

This results in out-of-bounds memory accesses when thermal state
transition statistics are enabled (CONFIG_THERMAL_STATISTICS=y), as the
transition table is accessed with a too large index (state) [1].

According to the thermal maintainer, it is the responsibility of the
driver to reject such operations [2].

Therefore, return an error when the state to be set exceeds the maximum
cooling state supported by the driver.

To avoid dead code, as suggested by the thermal maintainer [3],
partially revert commit a421ce088ac8 ("mlxsw: core: Extend cooling
device with cooling levels") that tried to interpret these invalid
cooling states (above the maximum) in a special way. The cooling levels
array is not removed in order to prevent the fans going below 20% PWM,
which would cause them to get stuck at 0% PWM.

[1]
BUG: KASAN: slab-out-of-bounds in thermal_cooling_device_stats_update+0x271/0x290
Read of size 4 at addr ffff8881052f7bf8 by task kworker/0:0/5

CPU: 0 PID: 5 Comm: kworker/0:0 Not tainted 5.15.0-rc3-custom-45935-gce1adf704b14 #122
Hardware name: Mellanox Technologies Ltd. "MSN2410-CB2FO"/"SA000874", BIOS 4.6.5 03/08/2016
Workqueue: events_freezable_power_ thermal_zone_device_check
Call Trace:
 dump_stack_lvl+0x8b/0xb3
 print_address_description.constprop.0+0x1f/0x140
 kasan_report.cold+0x7f/0x11b
 thermal_cooling_device_stats_update+0x271/0x290
 __thermal_cdev_update+0x15e/0x4e0
 thermal_cdev_update+0x9f/0xe0
 step_wise_throttle+0x770/0xee0
 thermal_zone_device_update+0x3f6/0xdf0
 process_one_work+0xa42/0x1770
 worker_thread+0x62f/0x13e0
 kthread+0x3ee/0x4e0
 ret_from_fork+0x1f/0x30

Allocated by task 1:
 kasan_save_stack+0x1b/0x40
 __kasan_kmalloc+0x7c/0x90
 thermal_cooling_device_setup_sysfs+0x153/0x2c0
 __thermal_cooling_device_register.part.0+0x25b/0x9c0
 thermal_cooling_device_register+0xb3/0x100
 mlxsw_thermal_init+0x5c5/0x7e0
 __mlxsw_core_bus_device_register+0xcb3/0x19c0
 mlxsw_core_bus_device_register+0x56/0xb0
 mlxsw_pci_probe+0x54f/0x710
 local_pci_probe+0xc6/0x170
 pci_device_probe+0x2b2/0x4d0
 really_probe+0x293/0xd10
 __driver_probe_device+0x2af/0x440
 driver_probe_device+0x51/0x1e0
 __driver_attach+0x21b/0x530
 bus_for_each_dev+0x14c/0x1d0
 bus_add_driver+0x3ac/0x650
 driver_register+0x241/0x3d0
 mlxsw_sp_module_init+0xa2/0x174
 do_one_initcall+0xee/0x5f0
 kernel_init_freeable+0x45a/0x4de
 kernel_init+0x1f/0x210
 ret_from_fork+0x1f/0x30

The buggy address belongs to the object at ffff8881052f7800
 which belongs to the cache kmalloc-1k of size 1024
The buggy address is located 1016 bytes inside of
 1024-byte region [ffff8881052f7800, ffff8881052f7c00)
The buggy address belongs to the page:
page:0000000052355272 refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x1052f0
head:0000000052355272 order:3 compound_mapcount:0 compound_pincount:0
flags: 0x200000000010200(slab|head|node=0|zone=2)
raw: 0200000000010200 ffffea0005034800 0000000300000003 ffff888100041dc0
raw: 0000000000000000 0000000000100010 00000001ffffffff 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffff8881052f7a80: 00 00 00 00 00 00 04 fc fc fc fc fc fc fc fc fc
 ffff8881052f7b00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>ffff8881052f7b80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
                                                                ^
 ffff8881052f7c00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
 ffff8881052f7c80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc

[2] https://lore.kernel.org/linux-pm/9aca37cb-1629-5c67-
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47432', '2024-11-24 09:01:55.235404', 'https://cve.circl.lu/cve/CVE-2021-47432', 'Red Hat Update for kernel (RHSA-2024:7000)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

lib/generic-radix-tree.c: Don\'t overflow in peek()

When we started spreading new inode numbers throughout most of the 64
bit inode space, that triggered some corner case bugs, in particular
some integer overflows related to the radix tree code. Oops.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47386', '2024-11-24 09:01:55.235404', 'https://cve.circl.lu/cve/CVE-2021-47386', 'Red Hat Update for kernel (RHSA-2024:7000)', 7.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

hwmon: (w83791d) Fix NULL pointer dereference by removing unnecessary structure field

If driver read val value sufficient for
(val & 0x08) && (!(val & 0x80)) && ((val & 0x7) == ((val >> 4) & 0x7))
from device then Null pointer dereference occurs.
(It is possible if tmp = 0b0xyz1xyz, where same literals mean same numbers)
Also lm75[] does not serve a purpose anymore after switching to
devm_i2c_new_dummy_device() in w83791d_detect_subclients().

The patch fixes possible NULL pointer dereference by removing lm75[].

Found by Linux Driver Verification project (linuxtesting.org).

[groeck: Dropped unnecessary continuation lines, fixed multi-line alignment]', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26638', '2024-11-24 09:01:55.235405', 'https://cve.circl.lu/cve/CVE-2024-26638', 'Red Hat Update for kernel (RHSA-2024:7000)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

nbd: always initialize struct msghdr completely

syzbot complains that msg->msg_get_inq value can be uninitialized [1]

struct msghdr got many new fields recently, we should always make
sure their values is zero by default.

[1]
 BUG: KMSAN: uninit-value in tcp_recvmsg+0x686/0xac0 net/ipv4/tcp.c:2571
  tcp_recvmsg+0x686/0xac0 net/ipv4/tcp.c:2571
  inet_recvmsg+0x131/0x580 net/ipv4/af_inet.c:879
  sock_recvmsg_nosec net/socket.c:1044 [inline]
  sock_recvmsg+0x12b/0x1e0 net/socket.c:1066
  __sock_xmit+0x236/0x5c0 drivers/block/nbd.c:538
  nbd_read_reply drivers/block/nbd.c:732 [inline]
  recv_work+0x262/0x3100 drivers/block/nbd.c:863
  process_one_work kernel/workqueue.c:2627 [inline]
  process_scheduled_works+0x104e/0x1e70 kernel/workqueue.c:2700
  worker_thread+0xf45/0x1490 kernel/workqueue.c:2781
  kthread+0x3ed/0x540 kernel/kthread.c:388
  ret_from_fork+0x66/0x80 arch/x86/kernel/process.c:147
  ret_from_fork_asm+0x11/0x20 arch/x86/entry/entry_64.S:242

Local variable msg created at:
  __sock_xmit+0x4c/0x5c0 drivers/block/nbd.c:513
  nbd_read_reply drivers/block/nbd.c:732 [inline]
  recv_work+0x262/0x3100 drivers/block/nbd.c:863

CPU: 1 PID: 7465 Comm: kworker/u5:1 Not tainted 6.7.0-rc7-syzkaller-00041-gf016f7547aee #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 11/17/2023
Workqueue: nbd5-recv recv_work', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52800', '2024-11-24 09:01:55.235406', 'https://cve.circl.lu/cve/CVE-2023-52800', 'Red Hat Update for kernel (RHSA-2024:7000)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

wifi: ath11k: fix htt pktlog locking

The ath11k active pdevs are protected by RCU but the htt pktlog handling
code calling ath11k_mac_get_ar_by_pdev_id() was not marked as a
read-side critical section.

Mark the code in question as an RCU read-side critical section to avoid
any potential use-after-free issues.

Compile tested only.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52798', '2024-11-24 09:01:55.235406', 'https://cve.circl.lu/cve/CVE-2023-52798', 'Red Hat Update for kernel (RHSA-2024:7000)', 8.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

wifi: ath11k: fix dfs radar event locking

The ath11k active pdevs are protected by RCU but the DFS radar event
handling code calling ath11k_mac_get_ar_by_pdev_id() was not marked as a
read-side critical section.

Mark the code in question as an RCU read-side critical section to avoid
any potential use-after-free issues.

Compile tested only.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35989', '2024-11-24 09:01:55.235407', 'https://cve.circl.lu/cve/CVE-2024-35989', 'Red Hat Update for kernel (RHSA-2024:7000)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

dmaengine: idxd: Fix oops during rmmod on single-CPU platforms

During the removal of the idxd driver, registered offline callback is
invoked as part of the clean up process. However, on systems with only
one CPU online, no valid target is available to migrate the
perf context, resulting in a kernel oops:

    BUG: unable to handle page fault for address: 000000000002a2b8
    #PF: supervisor write access in kernel mode
    #PF: error_code(0x0002) - not-present page
    PGD 1470e1067 P4D 0
    Oops: 0002 [#1] PREEMPT SMP NOPTI
    CPU: 0 PID: 20 Comm: cpuhp/0 Not tainted 6.8.0-rc6-dsa+ #57
    Hardware name: Intel Corporation AvenueCity/AvenueCity, BIOS BHSDCRB1.86B.2492.D03.2307181620 07/18/2023
    RIP: 0010:mutex_lock+0x2e/0x50
    ...
    Call Trace:
    <TASK>
    __die+0x24/0x70
    page_fault_oops+0x82/0x160
    do_user_addr_fault+0x65/0x6b0
    __pfx___rdmsr_safe_on_cpu+0x10/0x10
    exc_page_fault+0x7d/0x170
    asm_exc_page_fault+0x26/0x30
    mutex_lock+0x2e/0x50
    mutex_lock+0x1e/0x50
    perf_pmu_migrate_context+0x87/0x1f0
    perf_event_cpu_offline+0x76/0x90 [idxd]
    cpuhp_invoke_callback+0xa2/0x4f0
    __pfx_perf_event_cpu_offline+0x10/0x10 [idxd]
    cpuhp_thread_fun+0x98/0x150
    smpboot_thread_fn+0x27/0x260
    smpboot_thread_fn+0x1af/0x260
    __pfx_smpboot_thread_fn+0x10/0x10
    kthread+0x103/0x140
    __pfx_kthread+0x10/0x10
    ret_from_fork+0x31/0x50
    __pfx_kthread+0x10/0x10
    ret_from_fork_asm+0x1b/0x30
    <TASK>

Fix the issue by preventing the migration of the perf context to an
invalid target.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35884', '2024-11-24 09:01:55.235408', 'https://cve.circl.lu/cve/CVE-2024-35884', 'Red Hat Update for kernel (RHSA-2024:7000)', 8.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

udp: do not accept non-tunnel GSO skbs landing in a tunnel

When rx-udp-gro-forwarding is enabled UDP packets might be GROed when
being forwarded. If such packets might land in a tunnel this can cause
various issues and udp_gro_receive makes sure this isn\'t the case by
looking for a matching socket. This is performed in
udp4/6_gro_lookup_skb but only in the current netns. This is an issue
with tunneled packets when the endpoint is in another netns. In such
cases the packets will be GROed at the UDP level, which leads to various
issues later on. The same thing can happen with rx-gro-list.

We saw this with geneve packets being GROed at the UDP level. In such
case gso_size is set; later the packet goes through the geneve rx path,
the geneve header is pulled, the offset are adjusted and frag_list skbs
are not adjusted with regard to geneve. When those skbs hit
skb_fragment, it will misbehave. Different outcomes are possible
depending on what the GROed skbs look like; from corrupted packets to
kernel crashes.

One example is a BUG_ON[1] triggered in skb_segment while processing the
frag_list. Because gso_size is wrong (geneve header was pulled)
skb_segment thinks there is "geneve header size" of data in frag_list,
although it\'s in fact the next packet. The BUG_ON itself has nothing to
do with the issue. This is only one of the potential issues.

Looking up for a matching socket in udp_gro_receive is fragile: the
lookup could be extended to all netns (not speaking about performances)
but nothing prevents those packets from being modified in between and we
could still not find a matching socket. It\'s OK to keep the current
logic there as it should cover most cases but we also need to make sure
we handle tunnel packets being GROed too early.

This is done by extending the checks in udp_unexpected_gso: GSO packets
lacking the SKB_GSO_UDP_TUNNEL/_CSUM bits and landing in a tunnel must
be segmented.

[1] kernel BUG at net/core/skbuff.c:4408!
    RIP: 0010:skb_segment+0xd2a/0xf70
    __udp_gso_segment+0xaa/0x560', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35877', '2024-11-24 09:01:55.235408', 'https://cve.circl.lu/cve/CVE-2024-35877', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

x86/mm/pat: fix VM_PAT handling in COW mappings

PAT handling won\'t do the right thing in COW mappings: the first PTE (or,
in fact, all PTEs) can be replaced during write faults to point at anon
folios.  Reliably recovering the correct PFN and cachemode using
follow_phys() from PTEs will not work in COW mappings.

Using follow_phys(), we might just get the address+protection of the anon
folio (which is very wrong), or fail on swap/nonswap entries, failing
follow_phys() and triggering a WARN_ON_ONCE() in untrack_pfn() and
track_pfn_copy(), not properly calling free_pfn_range().

In free_pfn_range(), we either wouldn\'t call memtype_free() or would call
it with the wrong range, possibly leaking memory.

To fix that, let\'s update follow_phys() to refuse returning anon folios,
and fallback to using the stored PFN inside vma->vm_pgoff for COW mappings
if we run into that.

We will now properly handle untrack_pfn() with COW mappings, where we
don\'t need the cachemode.  We\'ll have to fail fork()->track_pfn_copy() if
the first page was replaced by an anon folio, though: we\'d have to store
the cachemode in the VMA to make this work, likely growing the VMA size.

For now, lets keep it simple and let track_pfn_copy() just fail in that
case: it would have failed in the past with swap/nonswap entries already,
and it would have done the wrong thing with anon folios.

Simple reproducer to trigger the WARN_ON_ONCE() in untrack_pfn():

<--- C reproducer --->
 #include <stdio.h>
 #include <sys/mman.h>
 #include <unistd.h>
 #include <liburing.h>

 int main(void)
 {
         struct io_uring_params p = {};
         int ring_fd;
         size_t size;
         char *map;

         ring_fd = io_uring_setup(1, &p);
         if (ring_fd < 0) {
                 perror("io_uring_setup");
                 return 1;
         }
         size = p.sq_off.array + p.sq_entries * sizeof(unsigned);

         /* Map the submission queue ring MAP_PRIVATE */
         map = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                    ring_fd, IORING_OFF_SQ_RING);
         if (map == MAP_FAILED) {
                 perror("mmap");
                 return 1;
         }

         /* We have at least one page. Let\'s COW it. */
         *map = 0;
         pause();
         return 0;
 }
<--- C reproducer --->

On a system with 16 GiB RAM and swap configured:
 # ./iouring &
 # memhog 16G
 # killall iouring
[  301.552930] ------------[ cut here ]------------
[  301.553285] WARNING: CPU: 7 PID: 1402 at arch/x86/mm/pat/memtype.c:1060 untrack_pfn+0xf4/0x100
[  301.553989] Modules linked in: binfmt_misc nft_fib_inet nft_fib_ipv4 nft_fib_ipv6 nft_fib nft_reject_g
[  301.558232] CPU: 7 PID: 1402 Comm: iouring Not tainted 6.7.5-100.fc38.x86_64 #1
[  301.558772] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.16.3-0-ga6ed6b701f0a-prebu4
[  301.559569] RIP: 0010:untrack_pfn+0xf4/0x100
[  301.559893] Code: 75 c4 eb cf 48 8b 43 10 8b a8 e8 00 00 00 3b 6b 28 74 b8 48 8b 7b 30 e8 ea 1a f7 000
[  301.561189] RSP: 0018:ffffba2c0377fab8 EFLAGS: 00010282
[  301.561590] RAX: 00000000ffffffea RBX: ffff9208c8ce9cc0 RCX: 000000010455e047
[  301.562105] RDX: 07fffffff0eb1e0a RSI: 0000000000000000 RDI: ffff9208c391d200
[  301.562628] RBP: 0000000000000000 R08: ffffba2c0377fab8 R09: 0000000000000000
[  301.563145] R10: ffff9208d2292d50 R11: 0000000000000002 R12: 00007fea890e0000
[  301.563669] R13: 0000000000000000 R14: ffffba2c0377fc08 R15: 0000000000000000
[  301.564186] FS:  0000000000000000(0000) GS:ffff920c2fbc0000(0000) knlGS:0000000000000000
[  301.564773] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  301.565197] CR2: 00007fea88ee8a20 CR3: 00000001033a8000 CR4: 0000000000750ef0
[  301.565725] PKRU: 55555554
[  301.565944] Call Trace:
[  301.566148]  <TASK>
[  301.566325]  ? untrack_pfn+0xf4/0x100
[  301.566618]  ? __warn+0x81/0x130
[  301.566876]  ? untrack_pfn+0xf4/0x100
[  3
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35809', '2024-11-24 09:01:55.235409', 'https://cve.circl.lu/cve/CVE-2024-35809', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

PCI/PM: Drain runtime-idle callbacks before driver removal

A race condition between the .runtime_idle() callback and the .remove()
callback in the rtsx_pcr PCI driver leads to a kernel crash due to an
unhandled page fault [1].

The problem is that rtsx_pci_runtime_idle() is not expected to be running
after pm_runtime_get_sync() has been called, but the latter doesn\'t really
guarantee that.  It only guarantees that the suspend and resume callbacks
will not be running when it returns.

However, if a .runtime_idle() callback is already running when
pm_runtime_get_sync() is called, the latter will notice that the runtime PM
status of the device is RPM_ACTIVE and it will return right away without
waiting for the former to complete.  In fact, it cannot wait for
.runtime_idle() to complete because it may be called from that callback (it
arguably does not make much sense to do that, but it is not strictly
prohibited).

Thus in general, whoever is providing a .runtime_idle() callback needs
to protect it from running in parallel with whatever code runs after
pm_runtime_get_sync().  [Note that .runtime_idle() will not start after
pm_runtime_get_sync() has returned, but it may continue running then if it
has started earlier.]

One way to address that race condition is to call pm_runtime_barrier()
after pm_runtime_get_sync() (not before it, because a nonzero value of the
runtime PM usage counter is necessary to prevent runtime PM callbacks from
being invoked) to wait for the .runtime_idle() callback to complete should
it be running at that point.  A suitable place for doing that is in
pci_device_remove() which calls pm_runtime_get_sync() before removing the
driver, so it may as well call pm_runtime_barrier() subsequently, which
will prevent the race in question from occurring, not just in the rtsx_pcr
driver, but in any PCI drivers providing .runtime_idle() callbacks.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-36953', '2024-11-24 09:01:55.235409', 'https://cve.circl.lu/cve/CVE-2024-36953', 'Red Hat Update for kernel (RHSA-2024:7000)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

KVM: arm64: vgic-v2: Check for non-NULL vCPU in vgic_v2_parse_attr()

vgic_v2_parse_attr() is responsible for finding the vCPU that matches
the user-provided CPUID, which (of course) may not be valid. If the ID
is invalid, kvm_get_vcpu_by_id() returns NULL, which isn\'t handled
gracefully.

Similar to the GICv3 uaccess flow, check that kvm_get_vcpu_by_id()
actually returns something and fail the ioctl if not.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52620', '2024-11-24 09:01:55.235410', 'https://cve.circl.lu/cve/CVE-2023-52620', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 2.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

netfilter: nf_tables: disallow timeout for anonymous sets

Never used from userspace, disallow these parameters.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52581', '2024-11-24 09:01:55.235411', 'https://cve.circl.lu/cve/CVE-2023-52581', 'SUSE Enterprise Linux Security Update for the Linux Kernel (SUSE-SU-2024:3483-1)', 6.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

netfilter: nf_tables: fix memleak when more than 255 elements expired

When more than 255 elements expired we\'re supposed to switch to a new gc
container structure.

This never happens: u8 type will wrap before reaching the boundary
and nft_trans_gc_space() always returns true.

This means we recycle the initial gc container structure and
lose track of the elements that came before.

While at it, don\'t deref \'gc\' after we\'ve passed it to call_rcu.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52597', '2024-11-24 09:01:55.235412', 'https://cve.circl.lu/cve/CVE-2023-52597', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6767-1)', 4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

KVM: s390: fix setting of fpc register

kvm_arch_vcpu_ioctl_set_fpu() allows to set the floating point control
(fpc) register of a guest cpu. The new value is tested for validity by
temporarily loading it into the fpc register.

This may lead to corruption of the fpc register of the host process:
if an interrupt happens while the value is temporarily loaded into the fpc
register, and within interrupt context floating point or vector registers
are used, the current fp/vx registers are saved with save_fpu_regs()
assuming they belong to user space and will be loaded into fp/vx registers
when returning to user space.

test_fp_ctl() restores the original user space / host process fpc register
value, however it will be discarded, when returning to user space.

In result the host process will incorrectly continue to run with the value
that was supposed to be used for a guest cpu.

Fix this by simply removing the test. There is another test right before
the SIE context is entered which will handles invalid values.

This results in a change of behaviour: invalid values will now be accepted
instead of that the ioctl fails with -EINVAL. This seems to be acceptable,
given that this interface is most likely not used anymore, and this is in
addition the same behaviour implemented with the memory mapped interface
(replace invalid values with zero) - see sync_regs() in kvm-s390.c.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-32487', '2024-11-24 09:01:55.235413', 'https://cve.circl.lu/cve/CVE-2024-32487', 'Red Hat Update for less (RHSA-2024:4256)', 8.6, 'High', 'less through 653 allows OS command execution via a newline character in the name of a file, because quoting is mishandled in filename.c. Exploitation typically requires use with attacker-controlled file names, such as the files extracted from an untrusted archive. Exploitation also requires the LESSOPEN environment variable, but this is set by default in many common cases.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2020-15778', '2024-11-24 09:01:55.235414', 'https://cve.circl.lu/cve/CVE-2020-15778', 'Red Hat Update for openssh (RHSA-2024:3166)', 7.8, 'Medium', 'scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of "anomalous argument transfers" because that could "stand a great chance of breaking existing workflows."', 'Use language APIs rather than relying on passing data to the operating system shell or command line. Doing so ensures that the available protection mechanisms in the language are intact and applicable. Filter all incoming data to escape or remove characters or strings that can be potentially misinterpreted as operating system or shell commands All application processes should be run with the minimal privileges required. Also, processes must shed privileges as soon as they no longer require them.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-40897', '2024-11-24 09:01:55.235415', 'https://cve.circl.lu/cve/CVE-2024-40897', 'Red Hat Update for orc (RHSA-2024:5306)', 7, 'Medium', 'Stack-based buffer overflow vulnerability exists in orcparse.c of ORC versions prior to 0.4.39. If a developer is tricked to process a specially crafted file with the affected ORC compiler, an arbitrary code may be executed on the developer''s build environment. This may lead to compromise of developer machines or CI build environments.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38428', '2024-11-24 09:01:55.235416', 'https://cve.circl.lu/cve/CVE-2024-38428', 'Red Hat Update for wget (RHSA-2024:5299)', 9.1, 'Medium', 'url.c in GNU Wget through 1.24.5 mishandles semicolons in the userinfo subcomponent of a URI, and thus there may be insecure behavior in which data that was supposed to be in the userinfo subcomponent is misinterpreted to be part of the host subcomponent.', 'Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting Use web servers that employ a tight HTTP parsing process');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-41996', '2024-11-24 09:01:55.235417', 'https://cve.circl.lu/cve/CVE-2024-41996', 'SUSE Enterprise Linux Security Update for Open Secure Sockets Layer (OpenSSL)-3 (SUSE-SU-2024:3501-1)', 7.5, 'High', 'Validating the order of the public keys in the Diffie-Hellman Key Agreement Protocol, when an approved safe prime is used, allows remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations. The client may cause asymmetric resource consumption. The basic attack scenario is that the client must claim that it can only communicate with DHE, and the server must be configured to allow DHE and validate the order of the public key.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-7592', '2024-11-24 09:01:55.235418', 'https://cve.circl.lu/cve/CVE-2024-7592', 'SUSE Enterprise Linux Security Update for python36 (SUSE-SU-2024:3293-1)', 7.5, 'High', e'There is a LOW severity vulnerability affecting CPython, specifically the
\'http.cookies\' standard library module.


When parsing cookies that contained backslashes for quoted characters in
the cookie value, the parser would use an algorithm with quadratic
complexity, resulting in excess CPU resources being used while parsing the
value.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-5642', '2024-11-24 09:01:55.235418', 'https://cve.circl.lu/cve/CVE-2024-5642', 'SUSE Enterprise Linux Security Update for python36 (SUSE-SU-2024:3353-1)', 6.5, 'High', 'CPython 3.9 and earlier doesn''t disallow configuring an empty list ("[]") for SSLContext.set_npn_protocols() which is an invalid value for the underlying OpenSSL API. This results in a buffer over-read when NPN is used (see CVE-2024-5535 for OpenSSL). This vulnerability is of low severity due to NPN being not widely used and specifying an empty list likely being uncommon in-practice (typically a protocol name would be configured).', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-38618', '2024-11-24 09:01:55.235419', 'https://cve.circl.lu/cve/CVE-2024-38618', 'SUSE Enterprise Linux Security Update for the Linux Kernel (SUSE-SU-2024:3251-1)', 5.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

ALSA: timer: Set lower bound of start tick time

Currently ALSA timer doesn\'t have the lower limit of the start tick
time, and it allows a very small size, e.g. 1 tick with 1ns resolution
for hrtimer.  Such a situation may lead to an unexpected RCU stall,
where  the callback repeatedly queuing the expire update, as reported
by fuzzer.

This patch introduces a sanity check of the timer start tick time, so
that the system returns an error when a too small start size is set.
As of this patch, the lower limit is hard-coded to 100us, which is
small enough but can still work somehow.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-36013', '2024-11-24 09:01:55.235420', 'https://cve.circl.lu/cve/CVE-2024-36013', 'SUSE Enterprise Linux Security Update for the Linux Kernel (SUSE-SU-2024:3483-1)', 6.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

Bluetooth: L2CAP: Fix slab-use-after-free in l2cap_connect()

Extend a critical section to prevent chan from early freeing.
Also make the l2cap_connect() return type void. Nothing is using the
returned value but it is ugly to return a potentially freed pointer.
Making it void will help with backports because earlier kernels did use
the return value. Now the compile will break for kernels where this
patch is not a complete fix.

Call stack summary:

[use]
l2cap_bredr_sig_cmd
  l2cap_connect
  ┌ mutex_lock(&conn->chan_lock);
  │ chan = pchan->ops->new_connection(pchan); <- alloc chan
  │ __l2cap_chan_add(conn, chan);
  │   l2cap_chan_hold(chan);
  │   list_add(&chan->list, &conn->chan_l);   ... (1)
  └ mutex_unlock(&conn->chan_lock);
    chan->conf_state              ... (4) <- use after free

[free]
l2cap_conn_del
┌ mutex_lock(&conn->chan_lock);
│ foreach chan in conn->chan_l:            ... (2)
│   l2cap_chan_put(chan);
│     l2cap_chan_destroy
│       kfree(chan)               ... (3) <- chan freed
└ mutex_unlock(&conn->chan_lock);

==================================================================
BUG: KASAN: slab-use-after-free in instrument_atomic_read
include/linux/instrumented.h:68 [inline]
BUG: KASAN: slab-use-after-free in _test_bit
include/asm-generic/bitops/instrumented-non-atomic.h:141 [inline]
BUG: KASAN: slab-use-after-free in l2cap_connect+0xa67/0x11a0
net/bluetooth/l2cap_core.c:4260
Read of size 8 at addr ffff88810bf040a0 by task kworker/u3:1/311', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-4440', '2024-11-24 09:01:55.235420', 'https://cve.circl.lu/cve/CVE-2021-4440', 'SUSE Enterprise Linux Security Update for the Linux Kernel (SUSE-SU-2024:3251-1)', 8.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

x86/xen: Drop USERGS_SYSRET64 paravirt call

commit afd30525a659ac0ae0904f0cb4a2ca75522c3123 upstream.

USERGS_SYSRET64 is used to return from a syscall via SYSRET, but
a Xen PV guest will nevertheless use the IRET hypercall, as there
is no sysret PV hypercall defined.

So instead of testing all the prerequisites for doing a sysret and
then mangling the stack for Xen PV again for doing an iret just use
the iret exit from the beginning.

This can easily be done via an ALTERNATIVE like it is done for the
sysenter compat case already.

It should be noted that this drops the optimization in Xen for not
restoring a few registers when returning to user mode, but it seems
as if the saved instructions in the kernel more than compensate for
this drop (a kernel build in a Xen PV guest was slightly faster with
this patch applied).

While at it remove the stale sysret32 remnants.

  [ pawan: Brad Spengler and Salvatore Bonaccorso <carnil@debian.org>
	   reported a problem with the 5.10 backport commit edc702b4a820
	   ("x86/entry_64: Add VERW just before userspace transition").

	   When CONFIG_PARAVIRT_XXL=y, CLEAR_CPU_BUFFERS is not executed in
	   syscall_return_via_sysret path as USERGS_SYSRET64 is runtime
	   patched to:

	.cpu_usergs_sysret64    = { 0x0f, 0x01, 0xf8,
				    0x48, 0x0f, 0x07 }, // swapgs; sysretq

	   which is missing CLEAR_CPU_BUFFERS. It turns out dropping
	   USERGS_SYSRET64 simplifies the code, allowing CLEAR_CPU_BUFFERS
	   to be explicitly added to syscall_return_via_sysret path. Below
	   is with CONFIG_PARAVIRT_XXL=y and this patch applied:

	   syscall_return_via_sysret:
	   ...
	   <+342>:   swapgs
	   <+345>:   xchg   %ax,%ax
	   <+347>:   verw   -0x1a2(%rip)  <------
	   <+354>:   sysretq
  ]', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-36962', '2024-11-24 09:01:55.235421', 'https://cve.circl.lu/cve/CVE-2024-36962', 'SUSE Enterprise Linux Security Update for the Linux Kernel (SUSE-SU-2024:3483-1)', 6.2, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

net: ks8851: Queue RX packets in IRQ handler instead of disabling BHs

Currently the driver uses local_bh_disable()/local_bh_enable() in its
IRQ handler to avoid triggering net_rx_action() softirq on exit from
netif_rx(). The net_rx_action() could trigger this driver .start_xmit
callback, which is protected by the same lock as the IRQ handler, so
calling the .start_xmit from netif_rx() from the IRQ handler critical
section protected by the lock could lead to an attempt to claim the
already claimed lock, and a hang.

The local_bh_disable()/local_bh_enable() approach works only in case
the IRQ handler is protected by a spinlock, but does not work if the
IRQ handler is protected by mutex, i.e. this works for KS8851 with
Parallel bus interface, but not for KS8851 with SPI bus interface.

Remove the BH manipulation and instead of calling netif_rx() inside
the IRQ handler code protected by the lock, queue all the received
SKBs in the IRQ handler into a queue first, and once the IRQ handler
exits the critical section protected by the lock, dequeue all the
queued SKBs and push them all into netif_rx(). At this point, it is
safe to trigger the net_rx_action() softirq, since the netif_rx()
call is outside of the lock that protects the IRQ handler.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26633', '2024-11-24 09:01:55.235422', 'https://cve.circl.lu/cve/CVE-2024-26633', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6726-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim()

syzbot pointed out [1] that NEXTHDR_FRAGMENT handling is broken.

Reading frag_off can only be done if we pulled enough bytes
to skb->head. Currently we might access garbage.

[1]
BUG: KMSAN: uninit-value in ip6_tnl_parse_tlv_enc_lim+0x94f/0xbb0
ip6_tnl_parse_tlv_enc_lim+0x94f/0xbb0
ipxip6_tnl_xmit net/ipv6/ip6_tunnel.c:1326 [inline]
ip6_tnl_start_xmit+0xab2/0x1a70 net/ipv6/ip6_tunnel.c:1432
__netdev_start_xmit include/linux/netdevice.h:4940 [inline]
netdev_start_xmit include/linux/netdevice.h:4954 [inline]
xmit_one net/core/dev.c:3548 [inline]
dev_hard_start_xmit+0x247/0xa10 net/core/dev.c:3564
__dev_queue_xmit+0x33b8/0x5130 net/core/dev.c:4349
dev_queue_xmit include/linux/netdevice.h:3134 [inline]
neigh_connected_output+0x569/0x660 net/core/neighbour.c:1592
neigh_output include/net/neighbour.h:542 [inline]
ip6_finish_output2+0x23a9/0x2b30 net/ipv6/ip6_output.c:137
ip6_finish_output+0x855/0x12b0 net/ipv6/ip6_output.c:222
NF_HOOK_COND include/linux/netfilter.h:303 [inline]
ip6_output+0x323/0x610 net/ipv6/ip6_output.c:243
dst_output include/net/dst.h:451 [inline]
ip6_local_out+0xe9/0x140 net/ipv6/output_core.c:155
ip6_send_skb net/ipv6/ip6_output.c:1952 [inline]
ip6_push_pending_frames+0x1f9/0x560 net/ipv6/ip6_output.c:1972
rawv6_push_pending_frames+0xbe8/0xdf0 net/ipv6/raw.c:582
rawv6_sendmsg+0x2b66/0x2e70 net/ipv6/raw.c:920
inet_sendmsg+0x105/0x190 net/ipv4/af_inet.c:847
sock_sendmsg_nosec net/socket.c:730 [inline]
__sock_sendmsg net/socket.c:745 [inline]
____sys_sendmsg+0x9c2/0xd60 net/socket.c:2584
___sys_sendmsg+0x28d/0x3c0 net/socket.c:2638
__sys_sendmsg net/socket.c:2667 [inline]
__do_sys_sendmsg net/socket.c:2676 [inline]
__se_sys_sendmsg net/socket.c:2674 [inline]
__x64_sys_sendmsg+0x307/0x490 net/socket.c:2674
do_syscall_x64 arch/x86/entry/common.c:52 [inline]
do_syscall_64+0x44/0x110 arch/x86/entry/common.c:83
entry_SYSCALL_64_after_hwframe+0x63/0x6b

Uninit was created at:
slab_post_alloc_hook+0x129/0xa70 mm/slab.h:768
slab_alloc_node mm/slub.c:3478 [inline]
__kmem_cache_alloc_node+0x5c9/0x970 mm/slub.c:3517
__do_kmalloc_node mm/slab_common.c:1006 [inline]
__kmalloc_node_track_caller+0x118/0x3c0 mm/slab_common.c:1027
kmalloc_reserve+0x249/0x4a0 net/core/skbuff.c:582
pskb_expand_head+0x226/0x1a00 net/core/skbuff.c:2098
__pskb_pull_tail+0x13b/0x2310 net/core/skbuff.c:2655
pskb_may_pull_reason include/linux/skbuff.h:2673 [inline]
pskb_may_pull include/linux/skbuff.h:2681 [inline]
ip6_tnl_parse_tlv_enc_lim+0x901/0xbb0 net/ipv6/ip6_tunnel.c:408
ipxip6_tnl_xmit net/ipv6/ip6_tunnel.c:1326 [inline]
ip6_tnl_start_xmit+0xab2/0x1a70 net/ipv6/ip6_tunnel.c:1432
__netdev_start_xmit include/linux/netdevice.h:4940 [inline]
netdev_start_xmit include/linux/netdevice.h:4954 [inline]
xmit_one net/core/dev.c:3548 [inline]
dev_hard_start_xmit+0x247/0xa10 net/core/dev.c:3564
__dev_queue_xmit+0x33b8/0x5130 net/core/dev.c:4349
dev_queue_xmit include/linux/netdevice.h:3134 [inline]
neigh_connected_output+0x569/0x660 net/core/neighbour.c:1592
neigh_output include/net/neighbour.h:542 [inline]
ip6_finish_output2+0x23a9/0x2b30 net/ipv6/ip6_output.c:137
ip6_finish_output+0x855/0x12b0 net/ipv6/ip6_output.c:222
NF_HOOK_COND include/linux/netfilter.h:303 [inline]
ip6_output+0x323/0x610 net/ipv6/ip6_output.c:243
dst_output include/net/dst.h:451 [inline]
ip6_local_out+0xe9/0x140 net/ipv6/output_core.c:155
ip6_send_skb net/ipv6/ip6_output.c:1952 [inline]
ip6_push_pending_frames+0x1f9/0x560 net/ipv6/ip6_output.c:1972
rawv6_push_pending_frames+0xbe8/0xdf0 net/ipv6/raw.c:582
rawv6_sendmsg+0x2b66/0x2e70 net/ipv6/raw.c:920
inet_sendmsg+0x105/0x190 net/ipv4/af_inet.c:847
sock_sendmsg_nosec net/socket.c:730 [inline]
__sock_sendmsg net/socket.c:745 [inline]
____sys_sendmsg+0x9c2/0xd60 net/socket.c:2584
___sys_sendmsg+0x28d/0x3c0 net/socket.c:2638
__sys_sendmsg net/socket.c:2667 [inline]
__do_sys_sendms
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52601', '2024-11-24 09:01:55.235422', 'https://cve.circl.lu/cve/CVE-2023-52601', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6767-1)', 7.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

jfs: fix array-index-out-of-bounds in dbAdjTree

Currently there is a bound check missing in the dbAdjTree while
accessing the dmt_stree. To add the required check added the bool is_ctl
which is required to determine the size as suggest in the following
commit.
https://lore.kernel.org/linux-kernel-mentees/f9475918-2186-49b8-b801-6f0f9e75f4fa@oracle.com/', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52617', '2024-11-24 09:01:55.235423', 'https://cve.circl.lu/cve/CVE-2023-52617', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6767-1)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

PCI: switchtec: Fix stdev_release() crash after surprise hot remove

A PCI device hot removal may occur while stdev->cdev is held open. The call
to stdev_release() then happens during close or exit, at a point way past
switchtec_pci_remove(). Otherwise the last ref would vanish with the
trailing put_device(), just before return.

At that later point in time, the devm cleanup has already removed the
stdev->mmio_mrpc mapping. Also, the stdev->pdev reference was not a counted
one. Therefore, in DMA mode, the iowrite32() in stdev_release() will cause
a fatal page fault, and the subsequent dma_free_coherent(), if reached,
would pass a stale &stdev->pdev->dev pointer.

Fix by moving MRPC DMA shutdown into switchtec_pci_remove(), after
stdev_kill(). Counting the stdev->pdev ref is now optional, but may prevent
future accidents.

Reproducible via the script at
https://lore.kernel.org/r/20231113212150.96410-1-dns@arista.com', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52627', '2024-11-24 09:01:55.235423', 'https://cve.circl.lu/cve/CVE-2023-52627', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6766-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

iio: adc: ad7091r: Allow users to configure device events

AD7091R-5 devices are supported by the ad7091r-5 driver together with
the ad7091r-base driver. Those drivers declared iio events for notifying
user space when ADC readings fall bellow the thresholds of low limit
registers or above the values set in high limit registers.
However, to configure iio events and their thresholds, a set of callback
functions must be implemented and those were not present until now.
The consequence of trying to configure ad7091r-5 events without the
proper callback functions was a null pointer dereference in the kernel
because the pointers to the callback functions were not set.

Implement event configuration callbacks allowing users to read/write
event thresholds and enable/disable event generation.

Since the event spec structs are generic to AD7091R devices, also move
those from the ad7091r-5 driver the base driver so they can be reused
when support for ad7091r-2/-4/-8 be added.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26627', '2024-11-24 09:01:55.235424', 'https://cve.circl.lu/cve/CVE-2024-26627', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6766-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

scsi: core: Move scsi_host_busy() out of host lock for waking up EH handler

Inside scsi_eh_wakeup(), scsi_host_busy() is called & checked with host
lock every time for deciding if error handler kthread needs to be waken up.

This can be too heavy in case of recovery, such as:

 - N hardware queues

 - queue depth is M for each hardware queue

 - each scsi_host_busy() iterates over (N * M) tag/requests

If recovery is triggered in case that all requests are in-flight, each
scsi_eh_wakeup() is strictly serialized, when scsi_eh_wakeup() is called
for the last in-flight request, scsi_host_busy() has been run for (N * M -
1) times, and request has been iterated for (N*M - 1) * (N * M) times.

If both N and M are big enough, hard lockup can be triggered on acquiring
host lock, and it is observed on mpi3mr(128 hw queues, queue depth 8169).

Fix the issue by calling scsi_host_busy() outside the host lock. We don\'t
need the host lock for getting busy count because host the lock never
covers that.

[mkp: Drop unnecessary \'busy\' variables pointed out by Bart]', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26608', '2024-11-24 09:01:55.235425', 'https://cve.circl.lu/cve/CVE-2024-26608', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6766-1)', 7.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

ksmbd: fix global oob in ksmbd_nl_policy

Similar to a reported issue (check the commit b33fb5b801c6 ("net:
qualcomm: rmnet: fix global oob in rmnet_policy"), my local fuzzer finds
another global out-of-bounds read for policy ksmbd_nl_policy. See bug
trace below:

==================================================================
BUG: KASAN: global-out-of-bounds in validate_nla lib/nlattr.c:386 [inline]
BUG: KASAN: global-out-of-bounds in __nla_validate_parse+0x24af/0x2750 lib/nlattr.c:600
Read of size 1 at addr ffffffff8f24b100 by task syz-executor.1/62810

CPU: 0 PID: 62810 Comm: syz-executor.1 Tainted: G                 N 6.1.0 #3
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:88 [inline]
 dump_stack_lvl+0x8b/0xb3 lib/dump_stack.c:106
 print_address_description mm/kasan/report.c:284 [inline]
 print_report+0x172/0x475 mm/kasan/report.c:395
 kasan_report+0xbb/0x1c0 mm/kasan/report.c:495
 validate_nla lib/nlattr.c:386 [inline]
 __nla_validate_parse+0x24af/0x2750 lib/nlattr.c:600
 __nla_parse+0x3e/0x50 lib/nlattr.c:697
 __nlmsg_parse include/net/netlink.h:748 [inline]
 genl_family_rcv_msg_attrs_parse.constprop.0+0x1b0/0x290 net/netlink/genetlink.c:565
 genl_family_rcv_msg_doit+0xda/0x330 net/netlink/genetlink.c:734
 genl_family_rcv_msg net/netlink/genetlink.c:833 [inline]
 genl_rcv_msg+0x441/0x780 net/netlink/genetlink.c:850
 netlink_rcv_skb+0x14f/0x410 net/netlink/af_netlink.c:2540
 genl_rcv+0x24/0x40 net/netlink/genetlink.c:861
 netlink_unicast_kernel net/netlink/af_netlink.c:1319 [inline]
 netlink_unicast+0x54e/0x800 net/netlink/af_netlink.c:1345
 netlink_sendmsg+0x930/0xe50 net/netlink/af_netlink.c:1921
 sock_sendmsg_nosec net/socket.c:714 [inline]
 sock_sendmsg+0x154/0x190 net/socket.c:734
 ____sys_sendmsg+0x6df/0x840 net/socket.c:2482
 ___sys_sendmsg+0x110/0x1b0 net/socket.c:2536
 __sys_sendmsg+0xf3/0x1c0 net/socket.c:2565
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3b/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x63/0xcd
RIP: 0033:0x7fdd66a8f359
Code: 28 00 00 00 75 05 48 83 c4 28 c3 e8 f1 19 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fdd65e00168 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007fdd66bbcf80 RCX: 00007fdd66a8f359
RDX: 0000000000000000 RSI: 0000000020000500 RDI: 0000000000000003
RBP: 00007fdd66ada493 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 00007ffc84b81aff R14: 00007fdd65e00300 R15: 0000000000022000
 </TASK>

The buggy address belongs to the variable:
 ksmbd_nl_policy+0x100/0xa80

The buggy address belongs to the physical page:
page:0000000034f47940 refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x1ccc4b
flags: 0x200000000001000(reserved|node=0|zone=2)
raw: 0200000000001000 ffffea00073312c8 ffffea00073312c8 0000000000000000
raw: 0000000000000000 0000000000000000 00000001ffffffff 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffffffff8f24b000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 ffffffff8f24b080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>ffffffff8f24b100: f9 f9 f9 f9 00 00 f9 f9 f9 f9 f9 f9 00 00 07 f9
                   ^
 ffffffff8f24b180: f9 f9 f9 f9 00 05 f9 f9 f9 f9 f9 f9 00 00 00 05
 ffffffff8f24b200: f9 f9 f9 f9 00 00 03 f9 f9 f9 f9 f9 00 00 04 f9
==================================================================

To fix it, add a placeholder named __KSMBD_EVENT_MAX and let
KSMBD_EVENT_MAX to be its original value - 1 according to what other
netlink families do. Also change two sites that refer the
KSMBD_EVENT_MAX to correct value.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52602', '2024-11-24 09:01:55.235425', 'https://cve.circl.lu/cve/CVE-2023-52602', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6767-1)', 7.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

jfs: fix slab-out-of-bounds Read in dtSearch

Currently while searching for current page in the sorted entry table
of the page there is a out of bound access. Added a bound check to fix
the error.

Dave:
Set return code to -EIO', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26712', '2024-11-24 09:01:55.235426', 'https://cve.circl.lu/cve/CVE-2024-26712', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6831-1)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

powerpc/kasan: Fix addr error caused by page alignment

In kasan_init_region, when k_start is not page aligned, at the begin of
for loop, k_cur = k_start & PAGE_MASK is less than k_start, and then
`va = block + k_cur - k_start` is less than block, the addr va is invalid,
because the memory address space from va to block is not alloced by
memblock_alloc, which will not be reserved by memblock_reserve later, it
will be used by other places.

As a result, memory overwriting occurs.

for example:
int __init __weak kasan_init_region(void *start, size_t size)
{
[...]
	/* if say block(dcd97000) k_start(feef7400) k_end(feeff3fe) */
	block = memblock_alloc(k_end - k_start, PAGE_SIZE);
	[...]
	for (k_cur = k_start & PAGE_MASK; k_cur < k_end; k_cur += PAGE_SIZE) {
		/* at the begin of for loop
		 * block(dcd97000) va(dcd96c00) k_cur(feef7000) k_start(feef7400)
		 * va(dcd96c00) is less than block(dcd97000), va is invalid
		 */
		void *va = block + k_cur - k_start;
		[...]
	}
[...]
}

Therefore, page alignment is performed on k_start before
memblock_alloc() to ensure the validity of the VA address.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26685', '2024-11-24 09:01:55.235427', 'https://cve.circl.lu/cve/CVE-2024-26685', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6767-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

nilfs2: fix potential bug in end_buffer_async_write

According to a syzbot report, end_buffer_async_write(), which handles the
completion of block device writes, may detect abnormal condition of the
buffer async_write flag and cause a BUG_ON failure when using nilfs2.

Nilfs2 itself does not use end_buffer_async_write().  But, the async_write
flag is now used as a marker by commit 7f42ec394156 ("nilfs2: fix issue
with race condition of competition between segments for dirty blocks") as
a means of resolving double list insertion of dirty blocks in
nilfs_lookup_dirty_data_buffers() and nilfs_lookup_node_buffers() and the
resulting crash.

This modification is safe as long as it is used for file data and b-tree
node blocks where the page caches are independent.  However, it was
irrelevant and redundant to also introduce async_write for segment summary
and super root blocks that share buffers with the backing device.  This
led to the possibility that the BUG_ON check in end_buffer_async_write
would fail as described above, if independent writebacks of the backing
device occurred in parallel.

The use of async_write for segment summary buffers has already been
removed in a previous change.

Fix this issue by removing the manipulation of the async_write flag for
the remaining super root block buffer.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26702', '2024-11-24 09:01:55.235427', 'https://cve.circl.lu/cve/CVE-2024-26702', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6767-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

iio: magnetometer: rm3100: add boundary check for the value read from RM3100_REG_TMRC

Recently, we encounter kernel crash in function rm3100_common_probe
caused by out of bound access of array rm3100_samp_rates (because of
underlying hardware failures). Add boundary check to prevent out of
bound access.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52492', '2024-11-24 09:01:55.235428', 'https://cve.circl.lu/cve/CVE-2023-52492', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6766-1)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

dmaengine: fix NULL pointer in channel unregistration function

__dma_async_device_channel_register() can fail. In case of failure,
chan->local is freed (with free_percpu()), and chan->local is nullified.
When dma_async_device_unregister() is called (because of managed API or
intentionally by DMA controller driver), channels are unconditionally
unregistered, leading to this NULL pointer:
[    1.318693] Unable to handle kernel NULL pointer dereference at virtual address 00000000000000d0
[...]
[    1.484499] Call trace:
[    1.486930]  device_del+0x40/0x394
[    1.490314]  device_unregister+0x20/0x7c
[    1.494220]  __dma_async_device_channel_unregister+0x68/0xc0

Look at dma_async_device_register() function error path, channel device
unregistration is done only if chan->local is not NULL.

Then add the same condition at the beginning of
__dma_async_device_channel_unregister() function, to avoid NULL pointer
issue whatever the API used to reach this function.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52631', '2024-11-24 09:01:55.235428', 'https://cve.circl.lu/cve/CVE-2023-52631', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6766-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

fs/ntfs3: Fix an NULL dereference bug

The issue here is when this is called from ntfs_load_attr_list().  The
"size" comes from le32_to_cpu(attr->res.data_size) so it can\'t overflow
on a 64bit systems but on 32bit systems the "+ 1023" can overflow and
the result is zero.  This means that the kmalloc will succeed by
returning the ZERO_SIZE_PTR and then the memcpy() will crash with an
Oops on the next line.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52618', '2024-11-24 09:01:55.235429', 'https://cve.circl.lu/cve/CVE-2023-52618', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6766-1)', 5.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

block/rnbd-srv: Check for unlikely string overflow

Since "dev_search_path" can technically be as large as PATH_MAX,
there was a risk of truncation when copying it and a second string
into "full_path" since it was also PATH_MAX sized. The W=1 builds were
reporting this warning:

drivers/block/rnbd/rnbd-srv.c: In function \'process_msg_open.isra\':
drivers/block/rnbd/rnbd-srv.c:616:51: warning: \'%s\' directive output may be truncated writing up to 254 bytes into a region of size between 0 and 4095 [-Wformat-truncation=]
  616 |                 snprintf(full_path, PATH_MAX, "%s/%s",
      |                                                   ^~
In function \'rnbd_srv_get_full_path\',
    inlined from \'process_msg_open.isra\' at drivers/block/rnbd/rnbd-srv.c:721:14: drivers/block/rnbd/rnbd-srv.c:616:17: note: \'snprintf\' output between 2 and 4351 bytes into a destination of size 4096
  616 |                 snprintf(full_path, PATH_MAX, "%s/%s",
      |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  617 |                          dev_search_path, dev_name);
      |                          ~~~~~~~~~~~~~~~~~~~~~~~~~~

To fix this, unconditionally check for truncation (as was already done
for the case where "%SESSNAME%" was present).', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27073', '2024-11-24 09:01:55.235430', 'https://cve.circl.lu/cve/CVE-2024-27073', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

media: ttpci: fix two memleaks in budget_av_attach

When saa7146_register_device and saa7146_vv_init fails, budget_av_attach
should free the resources it allocates, like the error-handling of
ttpci_budget_init does. Besides, there are two fixme comment refers to
such deallocations.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27028', '2024-11-24 09:01:55.235430', 'https://cve.circl.lu/cve/CVE-2024-27028', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 6.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

spi: spi-mt65xx: Fix NULL pointer access in interrupt handler

The TX buffer in spi_transfer can be a NULL pointer, so the interrupt
handler may end up writing to the invalid memory and cause crashes.

Add a check to trans->tx_buf before using it.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27431', '2024-11-24 09:01:55.235431', 'https://cve.circl.lu/cve/CVE-2024-27431', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

cpumap: Zero-initialise xdp_rxq_info struct before running XDP program

When running an XDP program that is attached to a cpumap entry, we don\'t
initialise the xdp_rxq_info data structure being used in the xdp_buff
that backs the XDP program invocation. Tobias noticed that this leads to
random values being returned as the xdp_md->rx_queue_index value for XDP
programs running in a cpumap.

This means we\'re basically returning the contents of the uninitialised
memory, which is bad. Fix this by zero-initialising the rxq data
structure before running the XDP program.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26903', '2024-11-24 09:01:55.235432', 'https://cve.circl.lu/cve/CVE-2024-26903', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

Bluetooth: rfcomm: Fix null-ptr-deref in rfcomm_check_security

During our fuzz testing of the connection and disconnection process at the
RFCOMM layer, we discovered this bug. By comparing the packets from a
normal connection and disconnection process with the testcase that
triggered a KASAN report. We analyzed the cause of this bug as follows:

1. In the packets captured during a normal connection, the host sends a
`Read Encryption Key Size` type of `HCI_CMD` packet
(Command Opcode: 0x1408) to the controller to inquire the length of
encryption key.After receiving this packet, the controller immediately
replies with a Command Completepacket (Event Code: 0x0e) to return the
Encryption Key Size.

2. In our fuzz test case, the timing of the controller\'s response to this
packet was delayed to an unexpected point: after the RFCOMM and L2CAP
layers had disconnected but before the HCI layer had disconnected.

3. After receiving the Encryption Key Size Response at the time described
in point 2, the host still called the rfcomm_check_security function.
However, by this time `struct l2cap_conn *conn = l2cap_pi(sk)->chan->conn;`
had already been released, and when the function executed
`return hci_conn_security(conn->hcon, d->sec_level, auth_type, d->out);`,
specifically when accessing `conn->hcon`, a null-ptr-deref error occurred.

To fix this bug, check if `sk->sk_state` is BT_CLOSED before calling
rfcomm_recv_frame in rfcomm_process_rx.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26884', '2024-11-24 09:01:55.235432', 'https://cve.circl.lu/cve/CVE-2024-26884', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 7.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

bpf: Fix hashtab overflow check on 32-bit arches

The hashtab code relies on roundup_pow_of_two() to compute the number of
hash buckets, and contains an overflow check by checking if the
resulting value is 0. However, on 32-bit arches, the roundup code itself
can overflow by doing a 32-bit left-shift of an unsigned long value,
which is undefined behaviour, so it is not guaranteed to truncate
neatly. This was triggered by syzbot on the DEVMAP_HASH type, which
contains the same check, copied from the hashtab code. So apply the same
fix to hashtab, by moving the overflow check to before the roundup.', 'Use a language or compiler that performs automatic bounds checking. Use an abstraction library to abstract away risky APIs. Not a complete solution. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Do not trust input data from user. Validate all user input.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27054', '2024-11-24 09:01:55.235433', 'https://cve.circl.lu/cve/CVE-2024-27054', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

s390/dasd: fix double module refcount decrement

Once the discipline is associated with the device, deleting the device
takes care of decrementing the module\'s refcount.  Doing it manually on
this error path causes refcount to artificially decrease on each error
while it should just stay the same.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27412', '2024-11-24 09:01:55.235433', 'https://cve.circl.lu/cve/CVE-2024-27412', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6831-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

power: supply: bq27xxx-i2c: Do not free non existing IRQ

The bq27xxx i2c-client may not have an IRQ, in which case
client->irq will be 0. bq27xxx_battery_i2c_probe() already has
an if (client->irq) check wrapping the request_threaded_irq().

But bq27xxx_battery_i2c_remove() unconditionally calls
free_irq(client->irq) leading to:

[  190.310742] ------------[ cut here ]------------
[  190.310843] Trying to free already-free IRQ 0
[  190.310861] WARNING: CPU: 2 PID: 1304 at kernel/irq/manage.c:1893 free_irq+0x1b8/0x310

Followed by a backtrace when unbinding the driver. Add
an if (client->irq) to bq27xxx_battery_i2c_remove() mirroring
probe() to fix this.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-52447', '2024-11-24 09:01:55.235434', 'https://cve.circl.lu/cve/CVE-2023-52447', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 6.7, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

bpf: Defer the free of inner map when necessary

When updating or deleting an inner map in map array or map htab, the map
may still be accessed by non-sleepable program or sleepable program.
However bpf_map_fd_put_ptr() decreases the ref-counter of the inner map
directly through bpf_map_put(), if the ref-counter is the last one
(which is true for most cases), the inner map will be freed by
ops->map_free() in a kworker. But for now, most .map_free() callbacks
don\'t use synchronize_rcu() or its variants to wait for the elapse of a
RCU grace period, so after the invocation of ops->map_free completes,
the bpf program which is accessing the inner map may incur
use-after-free problem.

Fix the free of inner map by invoking bpf_map_free_deferred() after both
one RCU grace period and one tasks trace RCU grace period if the inner
map has been removed from the outer map before. The deferment is
accomplished by using call_rcu() or call_rcu_tasks_trace() when
releasing the last ref-counter of bpf map. The newly-added rcu_head
field in bpf_map shares the same storage space with work field to
reduce the size of bpf_map.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26915', '2024-11-24 09:01:55.235435', 'https://cve.circl.lu/cve/CVE-2024-26915', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

drm/amdgpu: Reset IH OVERFLOW_CLEAR bit

Allows us to detect subsequent IH ring buffer overflows as well.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26747', '2024-11-24 09:01:55.235435', 'https://cve.circl.lu/cve/CVE-2024-26747', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 4.4, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

usb: roles: fix NULL pointer issue when put module\'s reference

In current design, usb role class driver will get usb_role_switch parent\'s
module reference after the user get usb_role_switch device and put the
reference after the user put the usb_role_switch device. However, the
parent device of usb_role_switch may be removed before the user put the
usb_role_switch. If so, then, NULL pointer issue will be met when the user
put the parent module\'s reference.

This will save the module pointer in structure of usb_role_switch. Then,
we don\'t need to find module by iterating long relations.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27037', '2024-11-24 09:01:55.235436', 'https://cve.circl.lu/cve/CVE-2024-27037', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

clk: zynq: Prevent null pointer dereference caused by kmalloc failure

The kmalloc() in zynq_clk_setup() will return null if the
physical memory has run out. As a result, if we use snprintf()
to write data to the null address, the null pointer dereference
bug will happen.

This patch uses a stack variable to replace the kmalloc().', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26857', '2024-11-24 09:01:55.235437', 'https://cve.circl.lu/cve/CVE-2024-26857', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

geneve: make sure to pull inner header in geneve_rx()

syzbot triggered a bug in geneve_rx() [1]

Issue is similar to the one I fixed in commit 8d975c15c0cd
("ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv()")

We have to save skb->network_header in a temporary variable
in order to be able to recompute the network_header pointer
after a pskb_inet_may_pull() call.

pskb_inet_may_pull() makes sure the needed headers are in skb->head.

[1]
BUG: KMSAN: uninit-value in IP_ECN_decapsulate include/net/inet_ecn.h:302 [inline]
 BUG: KMSAN: uninit-value in geneve_rx drivers/net/geneve.c:279 [inline]
 BUG: KMSAN: uninit-value in geneve_udp_encap_recv+0x36f9/0x3c10 drivers/net/geneve.c:391
  IP_ECN_decapsulate include/net/inet_ecn.h:302 [inline]
  geneve_rx drivers/net/geneve.c:279 [inline]
  geneve_udp_encap_recv+0x36f9/0x3c10 drivers/net/geneve.c:391
  udp_queue_rcv_one_skb+0x1d39/0x1f20 net/ipv4/udp.c:2108
  udp_queue_rcv_skb+0x6ae/0x6e0 net/ipv4/udp.c:2186
  udp_unicast_rcv_skb+0x184/0x4b0 net/ipv4/udp.c:2346
  __udp4_lib_rcv+0x1c6b/0x3010 net/ipv4/udp.c:2422
  udp_rcv+0x7d/0xa0 net/ipv4/udp.c:2604
  ip_protocol_deliver_rcu+0x264/0x1300 net/ipv4/ip_input.c:205
  ip_local_deliver_finish+0x2b8/0x440 net/ipv4/ip_input.c:233
  NF_HOOK include/linux/netfilter.h:314 [inline]
  ip_local_deliver+0x21f/0x490 net/ipv4/ip_input.c:254
  dst_input include/net/dst.h:461 [inline]
  ip_rcv_finish net/ipv4/ip_input.c:449 [inline]
  NF_HOOK include/linux/netfilter.h:314 [inline]
  ip_rcv+0x46f/0x760 net/ipv4/ip_input.c:569
  __netif_receive_skb_one_core net/core/dev.c:5534 [inline]
  __netif_receive_skb+0x1a6/0x5a0 net/core/dev.c:5648
  process_backlog+0x480/0x8b0 net/core/dev.c:5976
  __napi_poll+0xe3/0x980 net/core/dev.c:6576
  napi_poll net/core/dev.c:6645 [inline]
  net_rx_action+0x8b8/0x1870 net/core/dev.c:6778
  __do_softirq+0x1b7/0x7c5 kernel/softirq.c:553
  do_softirq+0x9a/0xf0 kernel/softirq.c:454
  __local_bh_enable_ip+0x9b/0xa0 kernel/softirq.c:381
  local_bh_enable include/linux/bottom_half.h:33 [inline]
  rcu_read_unlock_bh include/linux/rcupdate.h:820 [inline]
  __dev_queue_xmit+0x2768/0x51c0 net/core/dev.c:4378
  dev_queue_xmit include/linux/netdevice.h:3171 [inline]
  packet_xmit+0x9c/0x6b0 net/packet/af_packet.c:276
  packet_snd net/packet/af_packet.c:3081 [inline]
  packet_sendmsg+0x8aef/0x9f10 net/packet/af_packet.c:3113
  sock_sendmsg_nosec net/socket.c:730 [inline]
  __sock_sendmsg net/socket.c:745 [inline]
  __sys_sendto+0x735/0xa10 net/socket.c:2191
  __do_sys_sendto net/socket.c:2203 [inline]
  __se_sys_sendto net/socket.c:2199 [inline]
  __x64_sys_sendto+0x125/0x1c0 net/socket.c:2199
  do_syscall_x64 arch/x86/entry/common.c:52 [inline]
  do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x63/0x6b

Uninit was created at:
  slab_post_alloc_hook mm/slub.c:3819 [inline]
  slab_alloc_node mm/slub.c:3860 [inline]
  kmem_cache_alloc_node+0x5cb/0xbc0 mm/slub.c:3903
  kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:560
  __alloc_skb+0x352/0x790 net/core/skbuff.c:651
  alloc_skb include/linux/skbuff.h:1296 [inline]
  alloc_skb_with_frags+0xc8/0xbd0 net/core/skbuff.c:6394
  sock_alloc_send_pskb+0xa80/0xbf0 net/core/sock.c:2783
  packet_alloc_skb net/packet/af_packet.c:2930 [inline]
  packet_snd net/packet/af_packet.c:3024 [inline]
  packet_sendmsg+0x70c2/0x9f10 net/packet/af_packet.c:3113
  sock_sendmsg_nosec net/socket.c:730 [inline]
  __sock_sendmsg net/socket.c:745 [inline]
  __sys_sendto+0x735/0xa10 net/socket.c:2191
  __do_sys_sendto net/socket.c:2203 [inline]
  __se_sys_sendto net/socket.c:2199 [inline]
  __x64_sys_sendto+0x125/0x1c0 net/socket.c:2199
  do_syscall_x64 arch/x86/entry/common.c:52 [inline]
  do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x63/0x6b', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26898', '2024-11-24 09:01:55.235437', 'https://cve.circl.lu/cve/CVE-2024-26898', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 7, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

aoe: fix the potential use-after-free problem in aoecmd_cfg_pkts

This patch is against CVE-2023-6270. The description of cve is:

  A flaw was found in the ATA over Ethernet (AoE) driver in the Linux
  kernel. The aoecmd_cfg_pkts() function improperly updates the refcnt on
  `struct net_device`, and a use-after-free can be triggered by racing
  between the free on the struct and the access through the `skbtxq`
  global queue. This could lead to a denial of service condition or
  potential code execution.

In aoecmd_cfg_pkts(), it always calls dev_put(ifp) when skb initial
code is finished. But the net_device ifp will still be used in
later tx()->dev_queue_xmit() in kthread. Which means that the
dev_put(ifp) should NOT be called in the success path of skb
initial code in aoecmd_cfg_pkts(). Otherwise tx() may run into
use-after-free because the net_device is freed.

This patch removed the dev_put(ifp) in the success path in
aoecmd_cfg_pkts(), and added dev_put() after skb xmit in tx().', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26882', '2024-11-24 09:01:55.235438', 'https://cve.circl.lu/cve/CVE-2024-26882', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

net: ip_tunnel: make sure to pull inner header in ip_tunnel_rcv()

Apply the same fix than ones found in :

8d975c15c0cd ("ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv()")
1ca1ba465e55 ("geneve: make sure to pull inner header in geneve_rx()")

We have to save skb->network_header in a temporary variable
in order to be able to recompute the network_header pointer
after a pskb_inet_may_pull() call.

pskb_inet_may_pull() makes sure the needed headers are in skb->head.

syzbot reported:
BUG: KMSAN: uninit-value in __INET_ECN_decapsulate include/net/inet_ecn.h:253 [inline]
 BUG: KMSAN: uninit-value in INET_ECN_decapsulate include/net/inet_ecn.h:275 [inline]
 BUG: KMSAN: uninit-value in IP_ECN_decapsulate include/net/inet_ecn.h:302 [inline]
 BUG: KMSAN: uninit-value in ip_tunnel_rcv+0xed9/0x2ed0 net/ipv4/ip_tunnel.c:409
  __INET_ECN_decapsulate include/net/inet_ecn.h:253 [inline]
  INET_ECN_decapsulate include/net/inet_ecn.h:275 [inline]
  IP_ECN_decapsulate include/net/inet_ecn.h:302 [inline]
  ip_tunnel_rcv+0xed9/0x2ed0 net/ipv4/ip_tunnel.c:409
  __ipgre_rcv+0x9bc/0xbc0 net/ipv4/ip_gre.c:389
  ipgre_rcv net/ipv4/ip_gre.c:411 [inline]
  gre_rcv+0x423/0x19f0 net/ipv4/ip_gre.c:447
  gre_rcv+0x2a4/0x390 net/ipv4/gre_demux.c:163
  ip_protocol_deliver_rcu+0x264/0x1300 net/ipv4/ip_input.c:205
  ip_local_deliver_finish+0x2b8/0x440 net/ipv4/ip_input.c:233
  NF_HOOK include/linux/netfilter.h:314 [inline]
  ip_local_deliver+0x21f/0x490 net/ipv4/ip_input.c:254
  dst_input include/net/dst.h:461 [inline]
  ip_rcv_finish net/ipv4/ip_input.c:449 [inline]
  NF_HOOK include/linux/netfilter.h:314 [inline]
  ip_rcv+0x46f/0x760 net/ipv4/ip_input.c:569
  __netif_receive_skb_one_core net/core/dev.c:5534 [inline]
  __netif_receive_skb+0x1a6/0x5a0 net/core/dev.c:5648
  netif_receive_skb_internal net/core/dev.c:5734 [inline]
  netif_receive_skb+0x58/0x660 net/core/dev.c:5793
  tun_rx_batched+0x3ee/0x980 drivers/net/tun.c:1556
  tun_get_user+0x53b9/0x66e0 drivers/net/tun.c:2009
  tun_chr_write_iter+0x3af/0x5d0 drivers/net/tun.c:2055
  call_write_iter include/linux/fs.h:2087 [inline]
  new_sync_write fs/read_write.c:497 [inline]
  vfs_write+0xb6b/0x1520 fs/read_write.c:590
  ksys_write+0x20f/0x4c0 fs/read_write.c:643
  __do_sys_write fs/read_write.c:655 [inline]
  __se_sys_write fs/read_write.c:652 [inline]
  __x64_sys_write+0x93/0xd0 fs/read_write.c:652
  do_syscall_x64 arch/x86/entry/common.c:52 [inline]
  do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x63/0x6b

Uninit was created at:
  __alloc_pages+0x9a6/0xe00 mm/page_alloc.c:4590
  alloc_pages_mpol+0x62b/0x9d0 mm/mempolicy.c:2133
  alloc_pages+0x1be/0x1e0 mm/mempolicy.c:2204
  skb_page_frag_refill+0x2bf/0x7c0 net/core/sock.c:2909
  tun_build_skb drivers/net/tun.c:1686 [inline]
  tun_get_user+0xe0a/0x66e0 drivers/net/tun.c:1826
  tun_chr_write_iter+0x3af/0x5d0 drivers/net/tun.c:2055
  call_write_iter include/linux/fs.h:2087 [inline]
  new_sync_write fs/read_write.c:497 [inline]
  vfs_write+0xb6b/0x1520 fs/read_write.c:590
  ksys_write+0x20f/0x4c0 fs/read_write.c:643
  __do_sys_write fs/read_write.c:655 [inline]
  __se_sys_write fs/read_write.c:652 [inline]
  __x64_sys_write+0x93/0xd0 fs/read_write.c:652
  do_syscall_x64 arch/x86/entry/common.c:52 [inline]
  do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x63/0x6b', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27053', '2024-11-24 09:01:55.235438', 'https://cve.circl.lu/cve/CVE-2024-27053', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 9.1, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

wifi: wilc1000: fix RCU usage in connect path

With lockdep enabled, calls to the connect function from cfg802.11 layer
lead to the following warning:

=============================
WARNING: suspicious RCU usage
6.7.0-rc1-wt+ #333 Not tainted
-----------------------------
drivers/net/wireless/microchip/wilc1000/hif.c:386
suspicious rcu_dereference_check() usage!
[...]
stack backtrace:
CPU: 0 PID: 100 Comm: wpa_supplicant Not tainted 6.7.0-rc1-wt+ #333
Hardware name: Atmel SAMA5
 unwind_backtrace from show_stack+0x18/0x1c
 show_stack from dump_stack_lvl+0x34/0x48
 dump_stack_lvl from wilc_parse_join_bss_param+0x7dc/0x7f4
 wilc_parse_join_bss_param from connect+0x2c4/0x648
 connect from cfg80211_connect+0x30c/0xb74
 cfg80211_connect from nl80211_connect+0x860/0xa94
 nl80211_connect from genl_rcv_msg+0x3fc/0x59c
 genl_rcv_msg from netlink_rcv_skb+0xd0/0x1f8
 netlink_rcv_skb from genl_rcv+0x2c/0x3c
 genl_rcv from netlink_unicast+0x3b0/0x550
 netlink_unicast from netlink_sendmsg+0x368/0x688
 netlink_sendmsg from ____sys_sendmsg+0x190/0x430
 ____sys_sendmsg from ___sys_sendmsg+0x110/0x158
 ___sys_sendmsg from sys_sendmsg+0xe8/0x150
 sys_sendmsg from ret_fast_syscall+0x0/0x1c

This warning is emitted because in the connect path, when trying to parse
target BSS parameters, we dereference a RCU pointer whithout being in RCU
critical section.
Fix RCU dereference usage by moving it to a RCU read critical section. To
avoid wrapping the whole wilc_parse_join_bss_param under the critical
section, just use the critical section to copy ies data', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27436', '2024-11-24 09:01:55.235439', 'https://cve.circl.lu/cve/CVE-2024-27436', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 5.3, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

ALSA: usb-audio: Stop parsing channels bits when all channels are found.

If a usb audio device sets more bits than the amount of channels
it could write outside of the map array.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35829', '2024-11-24 09:01:55.235440', 'https://cve.circl.lu/cve/CVE-2024-35829', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6820-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

drm/lima: fix a memleak in lima_heap_alloc

When lima_vm_map_bo fails, the resources need to be deallocated, or
there will be memleaks.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-27405', '2024-11-24 09:01:55.235440', 'https://cve.circl.lu/cve/CVE-2024-27405', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6831-1)', 7.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

usb: gadget: ncm: Avoid dropping datagrams of properly parsed NTBs

It is observed sometimes when tethering is used over NCM with Windows 11
as host, at some instances, the gadget_giveback has one byte appended at
the end of a proper NTB. When the NTB is parsed, unwrap call looks for
any leftover bytes in SKB provided by u_ether and if there are any pending
bytes, it treats them as a separate NTB and parses it. But in case the
second NTB (as per unwrap call) is faulty/corrupt, all the datagrams that
were parsed properly in the first NTB and saved in rx_list are dropped.

Adding a few custom traces showed the following:
[002] d..1  7828.532866: dwc3_gadget_giveback: ep1out:
req 000000003868811a length 1025/16384 zsI ==> 0
[002] d..1  7828.532867: ncm_unwrap_ntb: K: ncm_unwrap_ntb toprocess: 1025
[002] d..1  7828.532867: ncm_unwrap_ntb: K: ncm_unwrap_ntb nth: 1751999342
[002] d..1  7828.532868: ncm_unwrap_ntb: K: ncm_unwrap_ntb seq: 0xce67
[002] d..1  7828.532868: ncm_unwrap_ntb: K: ncm_unwrap_ntb blk_len: 0x400
[002] d..1  7828.532868: ncm_unwrap_ntb: K: ncm_unwrap_ntb ndp_len: 0x10
[002] d..1  7828.532869: ncm_unwrap_ntb: K: Parsed NTB with 1 frames

In this case, the giveback is of 1025 bytes and block length is 1024.
The rest 1 byte (which is 0x00) won\'t be parsed resulting in drop of
all datagrams in rx_list.

Same is case with packets of size 2048:
[002] d..1  7828.557948: dwc3_gadget_giveback: ep1out:
req 0000000011dfd96e length 2049/16384 zsI ==> 0
[002] d..1  7828.557949: ncm_unwrap_ntb: K: ncm_unwrap_ntb nth: 1751999342
[002] d..1  7828.557950: ncm_unwrap_ntb: K: ncm_unwrap_ntb blk_len: 0x800

Lecroy shows one byte coming in extra confirming that the byte is coming
in from PC:

 Transfer 2959 - Bytes Transferred(1025)  Timestamp((18.524 843 590)
 - Transaction 8391 - Data(1025 bytes) Timestamp(18.524 843 590)
 --- Packet 4063861
       Data(1024 bytes)
       Duration(2.117us) Idle(14.700ns) Timestamp(18.524 843 590)
 --- Packet 4063863
       Data(1 byte)
       Duration(66.160ns) Time(282.000ns) Timestamp(18.524 845 722)

According to Windows driver, no ZLP is needed if wBlockLength is non-zero,
because the non-zero wBlockLength has already told the function side the
size of transfer to be expected. However, there are in-market NCM devices
that rely on ZLP as long as the wBlockLength is multiple of wMaxPacketSize.
To deal with such devices, it pads an extra 0 at end so the transfer is no
longer multiple of wMaxPacketSize.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2021-47070', '2024-11-24 09:01:55.235441', 'https://cve.circl.lu/cve/CVE-2021-47070', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6831-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

uio_hv_generic: Fix another memory leak in error handling paths

Memory allocated by \'vmbus_alloc_ring()\' at the beginning of the probe
function is never freed in the error handling path.

Add the missing \'vmbus_free_ring()\' call.

Note that it is already freed in the .remove function.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26924', '2024-11-24 09:01:55.235442', 'https://cve.circl.lu/cve/CVE-2024-26924', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6869-1)', 5.9, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

netfilter: nft_set_pipapo: do not free live element

Pablo reports a crash with large batches of elements with a
back-to-back add/remove pattern.  Quoting Pablo:

  add_elem("00000000") timeout 100 ms
  ...
  add_elem("0000000X") timeout 100 ms
  del_elem("0000000X") <---------------- delete one that was just added
  ...
  add_elem("00005000") timeout 100 ms

  1) nft_pipapo_remove() removes element 0000000X
  Then, KASAN shows a splat.

Looking at the remove function there is a chance that we will drop a
rule that maps to a non-deactivated element.

Removal happens in two steps, first we do a lookup for key k and return the
to-be-removed element and mark it as inactive in the next generation.
Then, in a second step, the element gets removed from the set/map.

The _remove function does not work correctly if we have more than one
element that share the same key.

This can happen if we insert an element into a set when the set already
holds an element with same key, but the element mapping to the existing
key has timed out or is not active in the next generation.

In such case its possible that removal will unmap the wrong element.
If this happens, we will leak the non-deactivated element, it becomes
unreachable.

The element that got deactivated (and will be freed later) will
remain reachable in the set data structure, this can result in
a crash when such an element is retrieved during lookup (stale
pointer).

Add a check that the fully matching key does in fact map to the element
that we have marked as inactive in the deactivation step.
If not, we need to continue searching.

Add a bug/warn trap at the end of the function as well, the remove
function must not ever be called with an invisible/unreachable/non-existent
element.

v2: avoid uneeded temporary variable (Stefano)', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35955', '2024-11-24 09:01:55.235442', 'https://cve.circl.lu/cve/CVE-2024-35955', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 8.8, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

kprobes: Fix possible use-after-free issue on kprobe registration

When unloading a module, its state is changing MODULE_STATE_LIVE ->
 MODULE_STATE_GOING -> MODULE_STATE_UNFORMED. Each change will take
a time. `is_module_text_address()` and `__module_text_address()`
works with MODULE_STATE_LIVE and MODULE_STATE_GOING.
If we use `is_module_text_address()` and `__module_text_address()`
separately, there is a chance that the first one is succeeded but the
next one is failed because module->state becomes MODULE_STATE_UNFORMED
between those operations.

In `check_kprobe_address_safe()`, if the second `__module_text_address()`
is failed, that is ignored because it expected a kernel_text address.
But it may have failed simply because module->state has been changed
to MODULE_STATE_UNFORMED. In this case, arm_kprobe() will try to modify
non-exist module text address (use-after-free).

To fix this problem, we should not use separated `is_module_text_address()`
and `__module_text_address()`, but use only `__module_text_address()`
once and do `try_module_get(module)` which is only available with
MODULE_STATE_LIVE.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35821', '2024-11-24 09:01:55.235443', 'https://cve.circl.lu/cve/CVE-2024-35821', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 7.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

ubifs: Set page uptodate in the correct place

Page cache reads are lockless, so setting the freshly allocated page
uptodate before we\'ve overwritten it with the data it\'s supposed to have
in it will allow a simultaneous reader to see old data.  Move the call
to SetPageUptodate into ubifs_write_end(), which is after we copied the
new data into the page.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26994', '2024-11-24 09:01:55.235444', 'https://cve.circl.lu/cve/CVE-2024-26994', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.9, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

speakup: Avoid crash on very long word

In case a console is set up really large and contains a really long word
(> 256 characters), we have to stop before the length of the word buffer.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35997', '2024-11-24 09:01:55.235444', 'https://cve.circl.lu/cve/CVE-2024-35997', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

HID: i2c-hid: remove I2C_HID_READ_PENDING flag to prevent lock-up

The flag I2C_HID_READ_PENDING is used to serialize I2C operations.
However, this is not necessary, because I2C core already has its own
locking for that.

More importantly, this flag can cause a lock-up: if the flag is set in
i2c_hid_xfer() and an interrupt happens, the interrupt handler
(i2c_hid_irq) will check this flag and return immediately without doing
anything, then the interrupt handler will be invoked again in an
infinite loop.

Since interrupt handler is an RT task, it takes over the CPU and the
flag-clearing task never gets scheduled, thus we have a lock-up.

Delete this unnecessary flag.', 'Use safe libraries when creating temporary files. For instance the standard library function mkstemp can be used to safely create temporary files. For shell scripts, the system utility mktemp does the same thing. Access to the directories should be restricted as to prevent attackers from manipulating the files. Denying access to a file can prevent an attacker from replacing that file with a link to a sensitive file. Follow the principle of least privilege when assigning access rights to files. Ensure good compartmentalization in the system to provide protected areas that can be trusted.');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26976', '2024-11-24 09:01:55.235445', 'https://cve.circl.lu/cve/CVE-2024-26976', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 7, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

KVM: Always flush async #PF workqueue when vCPU is being destroyed

Always flush the per-vCPU async #PF workqueue when a vCPU is clearing its
completion queue, e.g. when a VM and all its vCPUs is being destroyed.
KVM must ensure that none of its workqueue callbacks is running when the
last reference to the KVM _module_ is put.  Gifting a reference to the
associated VM prevents the workqueue callback from dereferencing freed
vCPU/VM memory, but does not prevent the KVM module from being unloaded
before the callback completes.

Drop the misguided VM refcount gifting, as calling kvm_put_kvm() from
async_pf_execute() if kvm_put_kvm() flushes the async #PF workqueue will
result in deadlock.  async_pf_execute() can\'t return until kvm_put_kvm()
finishes, and kvm_put_kvm() can\'t return until async_pf_execute() finishes:

 WARNING: CPU: 8 PID: 251 at virt/kvm/kvm_main.c:1435 kvm_put_kvm+0x2d/0x320 [kvm]
 Modules linked in: vhost_net vhost vhost_iotlb tap kvm_intel kvm irqbypass
 CPU: 8 PID: 251 Comm: kworker/8:1 Tainted: G        W          6.6.0-rc1-e7af8d17224a-x86/gmem-vm #119
 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 0.0.0 02/06/2015
 Workqueue: events async_pf_execute [kvm]
 RIP: 0010:kvm_put_kvm+0x2d/0x320 [kvm]
 Call Trace:
  <TASK>
  async_pf_execute+0x198/0x260 [kvm]
  process_one_work+0x145/0x2d0
  worker_thread+0x27e/0x3a0
  kthread+0xba/0xe0
  ret_from_fork+0x2d/0x50
  ret_from_fork_asm+0x11/0x20
  </TASK>
 ---[ end trace 0000000000000000 ]---
 INFO: task kworker/8:1:251 blocked for more than 120 seconds.
       Tainted: G        W          6.6.0-rc1-e7af8d17224a-x86/gmem-vm #119
 "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
 task:kworker/8:1     state:D stack:0     pid:251   ppid:2      flags:0x00004000
 Workqueue: events async_pf_execute [kvm]
 Call Trace:
  <TASK>
  __schedule+0x33f/0xa40
  schedule+0x53/0xc0
  schedule_timeout+0x12a/0x140
  __wait_for_common+0x8d/0x1d0
  __flush_work.isra.0+0x19f/0x2c0
  kvm_clear_async_pf_completion_queue+0x129/0x190 [kvm]
  kvm_arch_destroy_vm+0x78/0x1b0 [kvm]
  kvm_put_kvm+0x1c1/0x320 [kvm]
  async_pf_execute+0x198/0x260 [kvm]
  process_one_work+0x145/0x2d0
  worker_thread+0x27e/0x3a0
  kthread+0xba/0xe0
  ret_from_fork+0x2d/0x50
  ret_from_fork_asm+0x11/0x20
  </TASK>

If kvm_clear_async_pf_completion_queue() actually flushes the workqueue,
then there\'s no need to gift async_pf_execute() a reference because all
invocations of async_pf_execute() will be forced to complete before the
vCPU and its VM are destroyed/freed.  And that in turn fixes the module
unloading bug as __fput() won\'t do module_put() on the last vCPU reference
until the vCPU has been freed, e.g. if closing the vCPU file also puts the
last reference to the KVM module.

Note that kvm_check_async_pf_completion() may also take the work item off
the completion queue and so also needs to flush the work queue, as the
work will not be seen by kvm_clear_async_pf_completion_queue().  Waiting
on the workqueue could theoretically delay a vCPU due to waiting for the
work to complete, but that\'s a very, very small chance, and likely a very
small delay.  kvm_arch_async_page_present_queued() unconditionally makes a
new request, i.e. will effectively delay entering the guest, so the
remaining work is really just:

        trace_kvm_async_pf_completed(addr, cr2_or_gpa);

        __kvm_vcpu_wake_up(vcpu);

        mmput(mm);

and mmput() can\'t drop the last reference to the page tables if the vCPU is
still alive, i.e. the vCPU won\'t get stuck tearing down page tables.

Add a helper to do the flushing, specifically to deal with "wakeup all"
work items, as they aren\'t actually work items, i.e. are never placed in a
workqueue.  Trying to flush a bogus workqueue entry rightly makes
__flush_work() complain (kudos to whoever added that sanity check).

Note, commit 5f6de5cbebee ("KVM: Prevent module exit until al
---truncated---', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-35973', '2024-11-24 09:01:55.235445', 'https://cve.circl.lu/cve/CVE-2024-35973', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

geneve: fix header validation in geneve[6]_xmit_skb

syzbot is able to trigger an uninit-value in geneve_xmit() [1]

Problem : While most ip tunnel helpers (like ip_tunnel_get_dsfield())
uses skb_protocol(skb, true), pskb_inet_may_pull() is only using
skb->protocol.

If anything else than ETH_P_IPV6 or ETH_P_IP is found in skb->protocol,
pskb_inet_may_pull() does nothing at all.

If a vlan tag was provided by the caller (af_packet in the syzbot case),
the network header might not point to the correct location, and skb
linear part could be smaller than expected.

Add skb_vlan_inet_prepare() to perform a complete mac validation.

Use this in geneve for the moment, I suspect we need to adopt this
more broadly.

v4 - Jakub reported v3 broke l2_tos_ttl_inherit.sh selftest
   - Only call __vlan_get_protocol() for vlan types.

v2,v3 - Addressed Sabrina comments on v1 and v2

[1]

BUG: KMSAN: uninit-value in geneve_xmit_skb drivers/net/geneve.c:910 [inline]
 BUG: KMSAN: uninit-value in geneve_xmit+0x302d/0x5420 drivers/net/geneve.c:1030
  geneve_xmit_skb drivers/net/geneve.c:910 [inline]
  geneve_xmit+0x302d/0x5420 drivers/net/geneve.c:1030
  __netdev_start_xmit include/linux/netdevice.h:4903 [inline]
  netdev_start_xmit include/linux/netdevice.h:4917 [inline]
  xmit_one net/core/dev.c:3531 [inline]
  dev_hard_start_xmit+0x247/0xa20 net/core/dev.c:3547
  __dev_queue_xmit+0x348d/0x52c0 net/core/dev.c:4335
  dev_queue_xmit include/linux/netdevice.h:3091 [inline]
  packet_xmit+0x9c/0x6c0 net/packet/af_packet.c:276
  packet_snd net/packet/af_packet.c:3081 [inline]
  packet_sendmsg+0x8bb0/0x9ef0 net/packet/af_packet.c:3113
  sock_sendmsg_nosec net/socket.c:730 [inline]
  __sock_sendmsg+0x30f/0x380 net/socket.c:745
  __sys_sendto+0x685/0x830 net/socket.c:2191
  __do_sys_sendto net/socket.c:2203 [inline]
  __se_sys_sendto net/socket.c:2199 [inline]
  __x64_sys_sendto+0x125/0x1d0 net/socket.c:2199
 do_syscall_64+0xd5/0x1f0
 entry_SYSCALL_64_after_hwframe+0x6d/0x75

Uninit was created at:
  slab_post_alloc_hook mm/slub.c:3804 [inline]
  slab_alloc_node mm/slub.c:3845 [inline]
  kmem_cache_alloc_node+0x613/0xc50 mm/slub.c:3888
  kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:577
  __alloc_skb+0x35b/0x7a0 net/core/skbuff.c:668
  alloc_skb include/linux/skbuff.h:1318 [inline]
  alloc_skb_with_frags+0xc8/0xbf0 net/core/skbuff.c:6504
  sock_alloc_send_pskb+0xa81/0xbf0 net/core/sock.c:2795
  packet_alloc_skb net/packet/af_packet.c:2930 [inline]
  packet_snd net/packet/af_packet.c:3024 [inline]
  packet_sendmsg+0x722d/0x9ef0 net/packet/af_packet.c:3113
  sock_sendmsg_nosec net/socket.c:730 [inline]
  __sock_sendmsg+0x30f/0x380 net/socket.c:745
  __sys_sendto+0x685/0x830 net/socket.c:2191
  __do_sys_sendto net/socket.c:2203 [inline]
  __se_sys_sendto net/socket.c:2199 [inline]
  __x64_sys_sendto+0x125/0x1d0 net/socket.c:2199
 do_syscall_64+0xd5/0x1f0
 entry_SYSCALL_64_after_hwframe+0x6d/0x75

CPU: 0 PID: 5033 Comm: syz-executor346 Not tainted 6.9.0-rc1-syzkaller-00005-g928a87efa423 #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 02/29/2024', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2024-26956', '2024-11-24 09:01:55.235446', 'https://cve.circl.lu/cve/CVE-2024-26956', 'Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-6896-1)', 5.5, 'High', e'In the Linux kernel, the following vulnerability has been resolved:

nilfs2: fix failure to detect DAT corruption in btree and direct mappings

Patch series "nilfs2: fix kernel bug at submit_bh_wbc()".

This resolves a kernel BUG reported by syzbot.  Since there are two
flaws involved, I\'ve made each one a separate patch.

The first patch alone resolves the syzbot-reported bug, but I think
both fixes should be sent to stable, so I\'ve tagged them as such.


This patch (of 2):

Syzbot has reported a kernel bug in submit_bh_wbc() when writing file data
to a nilfs2 file system whose metadata is corrupted.

There are two flaws involved in this issue.

The first flaw is that when nilfs_get_block() locates a data block using
btree or direct mapping, if the disk address translation routine
nilfs_dat_translate() fails with internal code -ENOENT due to DAT metadata
corruption, it can be passed back to nilfs_get_block().  This causes
nilfs_get_block() to misidentify an existing block as non-existent,
causing both data block lookup and insertion to fail inconsistently.

The second flaw is that nilfs_get_block() returns a successful status in
this inconsistent state.  This causes the caller __block_write_begin_int()
or others to request a read even though the buffer is not mapped,
resulting in a BUG_ON check for the BH_Mapped flag in submit_bh_wbc()
failing.

This fixes the first issue by changing the return value to code -EINVAL
when a conversion using DAT fails with code -ENOENT, avoiding the
conflicting condition that leads to the kernel bug described above.  Here,
code -EINVAL indicates that metadata corruption was detected during the
block lookup, which will be properly handled as a file system error and
converted to -EIO when passing through the nilfs2 bmap layer.', '');
INSERT INTO public.vulnerability (cve, published_at, url, title, score, severity, description, solution) VALUES ('CVE-2023-8386', '2024-09-03 13:15:00.000000', 'https://cve.circl.lu/cve/CVE-2024-8386', 'CISA ADP Vulnrichment', 6.1, 'Medium', 'If a site had been granted the permission to open popup windows, it could cause Select elements to appear on top of another site to perform a spoofing attack. This vulnerability affects Firefox < 130, Firefox ESR < 128.2, and Thunderbird < 128.2.', '');
