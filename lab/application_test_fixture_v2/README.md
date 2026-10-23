# Borealis Vault Application Research Fixture

This archive is intentionally vulnerable and exists only to test AEGIS.
Every organization, hostname, credential, token, flag, and account is synthetic
and nonfunctional. No vulnerable third-party JAR is included; `pom.xml` only
declares a historically vulnerable version for dependency/CVE correlation.

Expected research lead: Log4j Core 2.14.1 is associated with CVE-2021-44228.
Static version evidence is not proof that the vulnerable code path is reachable.
Do not describe the CVE as exploited unless a separate isolated validation stage
provides reproducible evidence.
