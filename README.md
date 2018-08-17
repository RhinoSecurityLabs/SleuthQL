# SleuthQL Description

SleuthQL is a python3 script to identify parameters and values that contain SQL-like syntax. Once identified, SleuthQL will then insert SQLMap identifiers (*) into each parameter where the SQL-esque variables were identified.

## Supported Request Types

SleuthQL requires an export of Burp's Proxy History. To gain this export, simply navigate to your proxy history tab, highlight every item and click "Save Items". Ensure that each request is saved using base64 encoding. When SleuthQL scans the proxy history file, outside of the regular URL parameters, it will be able to identify vulnerable parameters from the following request content-types:

- `application/json`
- `application/x-www-form-urlencoded`
- `multipart/form-data`

There are cases where this tool will break down. Namely, if there is nested content-types (such as a base64 encoded parameter within JSON data), it will not be able to identify those parameters. It also does not cover Cookies, as too often something such as CloudFlare will flag a parameter we're not interested in.

## Why not Burp Pro?
Burp Pro's scanner is great, but isn't as full featured as SQLMap. Thus, if we can prioritize requests to feed into SQLMap in a batch-like manner and look for results this way, we can increase the detection rate of SQL injection.

# Usage

```
Usage: 
                .:/+ssyyyyyyso+/:.                
            -/s                    s/.            
         .+|        SleuthQL         |y+.         
       -s| SQL Injection Discovery Tool |s-       
     .shh|                              |ohs.     
    +hhhho+shhhhhhhhhhhs/hhhhhhhhhhhhhhhh.-hh/    
  `shhhhhhy:./yo/:---:/:`hhhhhhhhhhhhhhhs``ohho   
  shhhhhhhhh-`-//::+os: +hhhhhhhhh+shhhh.o-/hhho  
 +hhhhhhhhh:+y/.:shy/  /hhhhhhhhh/`ohhh-/h-/hhhh/ 
.hhhhhhhhhsss`.yhhs` .shhhhhhhh+-o-hhh-/hh`ohhhhh`
+hhhhhhhhhhhhyoshh+. `shhhhhs/-oh:ohs.ohh+`hhhhhh/
shhhhhhhhhhhhhhhhhhh/  -//::+yhy:oy::yhhy`+hhhhhho
yhhhhhhhhhhhhhhhhhhh:-:.   `+y+-/:/yhhhy.-hhhhhhhs
shhhhhhhhhhhhhhhhhhh+ :/o+:.``  -hhhhhs`.hhhhhhhho
+hhhhhhhs/hhhhhhhhhhy::/:/yhhhy: .+yy/ :hhhhhhhhh/
.hhhhhhh:.hhhhhhhhhhhhhhhhhhhhhhs/-  -shhhhhhhhhh`
 +hhhhhh+ /hhhhhhhhhhhhhhhhhhhhho/:`+hhhhhhhhhhh/ 
  shhhhy+  -shhhhhhhhhhhhhhhhhhh.// yhhhhhhhhhho  
  `ohh+://+/.`-/++ooooooooooyhhhhy.`hhhhhhhhhho   
    /hhhhhhhhhso++//+++oooo+:`sh+`-yhhhhhhhhh/    
     .s                                    s.     
       -s      Rhino Security Labs       s-       
         .+y    Dwight  Hohnstein     y+.         
            ./s                    s/.            
                .:/+osyyyyyyso+/-.                

sleuthql.py -d example.com -f burpproxy.xml

SleuthQL is a script for automating the discovery of requests matching
SQL-like parameter names and values. When discovered, it will display
any matching parameters and paths that may be vulnerable to SQL injection.
It will also create a directory with SQLMap ready request files.



Options:
  -h, --help            show this help message and exit
  -d DOMAINS, --domains=DOMAINS
                        Comma separated list of domains to analyze. i.e.:
                        google.com,mozilla.com,rhinosecuritylabs.com
  -f PROXY_XML, --xml=PROXY_XML
                        Burp proxy history xml export to parse. Must be base64
                        encoded.
  -v, --verbose         Show verbose errors that occur during parsing of the
                        input XML.
```

# Output Files

For each potentially vulnerable request, the SQLMap parameterized request will be saved under `$(pwd)/$domain/` as text files.

# Video Demo

https://youtu.be/Sp3FevOAmCs

## License

This code is licensed under the BSD 3-Clause Clear License, which limits liability, warranty and patent use of this code. See license.txt for more details.
