Mail 【golang send mail package】
------

##  Mail: send mail support AUTH:

* `LOGIN` : mail.LoginAuth(email.Username, email.Password)
* `CRAM-MD5`: smtp.CRAMMD5Auth(email.Username, email.Password)
* `PLAIN` : smtp.PlainAuth(email.Identity, email.Username, email.Password, email.Host)
* `NTLM`: mail.NTLMAuth(email.Host, email.Username, email.Password, mail.NTLMVersion1) # mail.NTLMVersion2 也支持

## Mail: send mail support Secure:

* SSL
* TLS
* 非安全加密


   
