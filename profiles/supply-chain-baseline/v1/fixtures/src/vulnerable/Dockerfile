FROM scratch
# log4j-core 2.14.1: Log4Shell (CVE-2021-44228), deliberately vulnerable fixture
ADD --checksum=sha256:ade7402a70667a727635d5c4c29495f4ff96f061f12539763f6f123973b465b0 \
    https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar /app/lib/
COPY app/ /app/src/
