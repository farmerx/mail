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

## Mail: Use github.com/farmerx/mail

```
email := NewEMail(`{"port":25}`)
email.From = `farmerx@163.com`
email.Host = `smtp.163.com`
email.Port = int(25) // [587 NTLM AUTH] [465，994]
email.Username = `Farmerx`
email.Secure = `` // SSL，TSL
email.Password = `************`
authType := `LOGIN`
switch authType {
case ``:
	email.Auth = nil
case `LOGIN`:
	email.Auth = LoginAuth(email.Username, email.Password)
case `CRAM-MD5`:
	email.Auth = smtp.CRAMMD5Auth(email.Username, email.Password)
case `PLAIN`:
	email.Auth = smtp.PlainAuth(email.Identity, email.Username, email.Password, email.Host)
case `NTLM`:
	email.Auth = NTLMAuth(email.Host, email.Username, email.Password, NTLMVersion1)
default:
	email.Auth = smtp.PlainAuth(email.Identity, email.Username, email.Password, email.Host)
}

email.To = []string{`bibinbin@360.net`}
email.Subject = `send mail success`
email.Text = "尊敬的用户：\r\n   您好，附件中是您订阅的报表，请注意查收。"
//email.AttachFile(reportFile)
if err := email.Send(); err != nil {
      fmt.Println(err)
}

```


   
