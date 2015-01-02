py-cpanel-email-api
===================

**Python Library for WHM/Cpanel's API2 Email Module** 

https://documentation.cpanel.net/display/SDK/cPanel+API+2+-+Email

- Author: Benton Snyder
- Website: http://bensnyde.me
- Created: 8/15/13
- Revised: 1/1/15

Installation
---
```
# pip install py-cpanel-email-api
```

Usage
---
```
from cpanel_email_api import CpanelEmail
cpanel = CpanelEmail("whm.example.com", "root", "strongpassword", "some_cpanel_user")
print cpanel.listpops()
```
