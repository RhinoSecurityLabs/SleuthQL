#!/usr/bin/env python3
try:
    from bs4 import BeautifulSoup
except ImportError as e:
    print('[-] Missing dependency BeautifulSoup. Install with python -m pip3 install bs4')
    exit(1)
from optparse import OptionParser
from urllib.parse import urlparse, unquote
import base64
import json
import re
from types import GeneratorType
from os import mkdir
# Custom sql-like regex
from settings import compiledSql


####################
# Helper functions #
####################

# def isBase64(s):
#     """
#     Given a string, determine if it's base64 encoded.
#     This function is broken. :'(
#     """
#     try:
#         if base64.b64encode(base64.decodestring(s)) == s:
#             return True;
#     except Exception:
#         pass;
#     return False;

def isInt(s):
    """
    Given a string, see if it is an integer.
    """
    try:
        s = int(s)
        return True
    except ValueError as e:
        return False

def isJsonDict(s):
    """
    Take a string and determine if valid JSON.
    """
    try:
        data = json.loads(s)
        return type(data) == dict
    except ValueError:
        return False
    
def parse_item(item):
    """
    Take bs4 representation of a proxy history 'item' from xml and
    return a dictionary representation of it.

    Parameters:
        item(BeautifulSoup): BeautifulSoup object of one of Burp's <item> blocks from XML.

    Returns:
        dict: The BeautifulSoup object turned into a dictionary.

    Example input:

    <item>
    <time>Thu Feb 15 10:43:42 PST 2018</time>
    <url>http://detectportal.firefox.com/success.txt</url>
    <host ip="207.108.220.187">detectportal.firefox.com</host>
    <port>80</port>
    <protocol>http</protocol>
    <method>GET</method>
    <path>/success.txt</path>
    <extension>txt</extension>
    <request base64="true">R0VUIC9zdWNjZXNzLnR4dCBIVFRQLzEuMQ0KSG9zdDogZGV0ZWN0cG9ydGFsLmZpcmVmb3guY29tDQpVc2VyLUFnZW50Oi
    3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjo1OC4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzU4LjANCkFjY2VwdDogKi
    QpBY2NlcHQtTGFuZ3VhZ2U6IGVuLVVTLGVuO3E9MC41DQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNCkNhY2hlLUNvbnRyb2w6IG5vLWNhY2
    QpQcmFnbWE6IG5vLWNhY2hlDQpDb25uZWN0aW9uOiBjbG9zZQ0KDQo=</request>
    <status>200</status>
    <responselength>379</responselength>
    <mimetype>text</mimetype>
    <response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IHRleHQvcGxhaW4NCkNvbnRlbnQtTGVuZ3RoOiA4DQpMYXN0LU1vZ
    aWVkOiBNb24sIDE1IE1heSAyMDE3IDE4OjA0OjQwIEdNVA0KRVRhZzogImFlNzgwNTg1ZjQ5Yjk0Y2UxNDQ0ZWI3ZDI4OTA2MTIzIg0KQWNjZXB0LVJhb
    czogYnl0ZXMNClNlcnZlcjogQW1hem9uUzMNClgtQW16LUNmLUlkOiBMTi0yVWxtZVpic0FrbGxvYzJOSElMZWhoN0RBTHZGOTF0RzZBYWNBNXdlX2ZKN
    anRyLXc9PQ0KQ2FjaGUtQ29udHJvbDogbm8tY2FjaGUsIG5vLXN0b3JlLCBtdXN0LXJldmFsaWRhdGUNCkRhdGU6IFRodSwgMTUgRmViIDIwMTggMTg6N
    NDcgR01UDQpDb25uZWN0aW9uOiBjbG9zZQ0KDQpzdWNjZXNzCg==</response>
    <comment/>
    </item>

    Returns:
        {
            "url": "http://detectportal.firefox.com/success.txt",
            "host": "detectportal.firefox.com",
            "port": "80",
            "protocol": "http",
            "method": "GET",
            ...
        }
    """
    results = {}
    for tag in item.findChildren():
        results[tag.name] = tag.text
    return results

def parse_formdata_params(data):
    """
    Takes a formdata request body and parses it into key/value pairs.
    
    Parameters:
        data(str): Input string of multipart form data to parse.

    Returns:
        list: List of dictionaries in {key:value} pairs.
    """
    results = []
    diced = data.split("\r\n")
    tmpkey = ""
    count = 0
    for line in diced:
        if tmpkey:
            # do something
            if count == 1:
                results.append({tmpkey:line.strip()})
                count = 0
                tmpkey = ""
            else:
                count += 1
        else:
            # Looking for the key
            if "Content-Disposition" in line:
                # Found the line with key!
                searchterm = 'name="'
                searchlen  = len(searchterm)
                nameloc = line.find(searchterm)
                keystart = nameloc + searchlen
                keyend = line.find('"', keystart)
                tmpkey = line[keystart:keyend]
    return results


def parse_xml_body(data, basekey=None):
    """
    Takes nested BeautifulSoup object and returns all key value pairs.
    
    Parameters:
        data (BeautifulSoup): XML BeautifulSoup object

    Returns:
        list: List of dictionaries of key:val pairs
    """
    results = []
    if data.findChildren():
        # It's a parent node, recurse!
        for child in data.findChildren():
            results += parse_xml_body(child)
    else:
        # No children, easy enough.
        results.append({data.name: data.text})
    return results

def parse_json_body(data, basekey=None):
    """
    Takes nested json object and returns all key names associated with them.

    Parameters:
        data(json): JSON object that may or may not have nested data structures in it.

    Returns:
        list: List of dictionaries that are key:value pairs.
    """
    
    results = []
    
    if type(data) == dict:
        for key, val in data.items():
            if type(val) == int or type(val) == str:
                results.append({key:val})
            else: # Must be a list or dict
                results += parse_json_body(val, basekey=key)
    elif type(data) == list:
        for item in data:
            if type(item) == int or type(item) == str:
                results.append({basekey:item})
            else:
                results += parse_json_body(item, basekey=basekey)
    else:
        if not basekey:
            raise Exception("No base key defined for data {}".format(data))
        results.append({basekey:data})
    return results

#### End Helper Functions ####

def createParameterDictionary(url, body=None, is_json=False, is_xml=False, is_formdata=False):
    """
    Requires the data sent in a request along with the content-type.
    Returns a dictionary of key/value pairs for all parameters sent
    with their associated values.

    Parameters:
        url(str)                   : The endpoint that requires parsing, such as "/search?query=asdf&filter=1234"
        body(str)(optional)        : Body of the HTTP request, if present.
        is_json(bool)(optional)    : Indicates whether or not the body is JSON data.
        is_xml(bool)(optional)     : Indicates whether or not the body is XML data.
        is_formdata(bool)(optional): Indicates whether or not the body is multipart/form-data.
    
        Note: The "is_*" variables should only be passed when body is an unusual content-type.

    Returns:
        dict

    Example return:

    {
        'param1': ['value1'],
        'param2': ['value2', 'value3'],
    }
    """

    querystring = urlparse(url).query
    params = {}
    if querystring:
        # There there is query params, add them to dict
        keyvalue_pairs = querystring.split("&")
        for pair in keyvalue_pairs:
            info = pair.split("=")
            key = info[0]
            val = "".join(info[1:])
            # key, val = pair.split("=")
            # Check for existance of key in dict
            if key not in params.keys():
                params[key] = set()
            # Update value set for param
            params[key].update([val])
    
    if body:
        if is_json:
            # Should be a list of dicts containing k/v pairs i.e.
            # [{'a': 'b'}, {'c':'d'}]
            jsonparams = parse_json_body(body)
            for jsonparam in jsonparams:
                for key, val in jsonparam.items():
                    # This brick was meant to decode base64 values. Unfortunately,
                    # I haven't figured out a way to do this reliably that makes sense.
                    # Do value parsing
                    # if isBase64(val):
                    #     # Returns another bytes object
                    #     val = base64.b64decode(val)
                    if key not in params.keys():
                        # Initialize dict
                        params[key] = set()
                    # Update
                    params[key].update([val])
        elif is_xml:
            # Do some xml parsing
            soup = BeautifulSoup(body, 'xml')
            xml_params = parse_xml_body(soup)
            for xmlparam in xml_params:
                for key, val in xmlparam.items():
                    if key not in params.keys():
                        params[key] = set()
                    params[key].update([val])
        elif is_formdata:
            # Do some form data parsing
            formdata_params = parse_formdata_params(body)
            for formparam in formdata_params:
                for key, val in formparam.items():
                    if key not in params.keys():
                        params[key] = set()
                    params[key].update([val])
        else:
            # Regular content type, split 'em and add em
            # Some other mimetype we assume to be application/url-encoded
            # Some query string like key1=val1&key2=val2
            reqparams = body.split("&")
            # Now a list like ['key1=val1', 'key2%3eval2']
            urlparsed_params = [unquote(x) for x in reqparams]
            for param in urlparsed_params:
                info = param.split("=")
                key = info[0]
                val = "".join(info[1:])
                # Let's do the value parsing/decoding here as well.
                if isJsonDict(val):
                    # Feed this back to unfurl nested json param
                    val = json.loads(val)
                    jsonParams = createParameterDictionary("", val, is_json=True)
                    # Have our parameter dict, let's just add it to the overall
                    # Params
                    for jkey, jval in jsonParams.items():
                        if jkey not in params.keys():
                            params[jkey] = jval
                        else:
                            params[jkey].update(jval)
                # If Base64 data is discovered, stick it in an elif block here.
                # Otherwise, continue to the else block.
                else:
                    # not json or base64, let's just do normal adding
                    if key not in params.keys():
                        params[key] = set()
                    params[key].update([val])
    return params


def parse_xml(soup, domains, verbose=False):
    """
    Parse a BeautifulSoup4 object which is an xml export
    of burp's proxy history. Domains is a list of domains to look
    for.

    Parameters:
        soup(BeautifulSoup) : BeautfiulSoup object which is parsed
                              from Burp's Proxy XML.
        domains(iterable)   : List of strings which identify which
                              domains to fetch history for.
        verbose(bool)       : Boolean if whether or not to output
                              information regarding errors in parsing
                              HTTP requests.
    Returns:
        dict

    Example return:

    {
        "domain": {
            "/path1": {
                "GET": {
                    "params": {
                        "key1": {"val1","val2"} # This is a set,
                        "key2": {"val3","val4"}
                    },
                    "requests": [
                        "GET /path1?key1=val1\r\nHost: testhost.com\r\n..."
                    ]
                },
                "POST": {
                    "params": {
                        "key1": {"val1","val2"} # This is a set,
                        "key2": {"val3","val4"}
                    },
                    "requests": [
                        "POST /path1\r\nHost: testhost.com\r\n....\r\n\r\nkey1=val1&key2=val3"
                    ]
                }
            },

            "path2": {...},
            
            }
    }
    """
    proxy_matches = {}
    items = soup.findAll('item')
    # Filter proxy history based on domain
    for domain in domains:
        domitems = filter(lambda x: domain in x.find('host').text, items)
        if domitems:
            # Python3 returns filter object instead of list
            domitems = list(domitems)
            proxy_matches[domain] = domitems
    print('[+] Found {} requests from proxy history.'.format(len(items)))
    for k, v in proxy_matches.items():
        print('[+] Found {} requests matching {} hostname.'.format(len(v), k))
    print()
    print('\n[+] Sorting...')

    # Start building results

    results = {}

    for domain, items in proxy_matches.items():
        domresults = {}
        for item in items:
            # Data is a dict that translate bs4 data into dict obj
            data = parse_item(item)
            path = data['path'].split("?")[0]
            method = data['method']
            if path not in domresults.keys():
                domresults[path] = {}

            if method not in domresults[path].keys():
                domresults[path][method] = {"params": {},
                                            "requests": []}
       
            # Only query params to add, so add them and move on.
            # domresults[path][method]['params']['QUERY'].update(params['QUERY'])
            params = createParameterDictionary(data['url'])
            b64req = data['request']
            request = base64.b64decode(b64req)
            try:
                request = request.decode('utf-8')
            except UnicodeDecodeError as e:
                # Burp encoding happened. Give up.
                request = ""
            if method != "GET":
                # Method is POST/PUT/DELETE, potentially more data.
                # the decoding of request can be done probably by fetching attr of element
                try:
                    # Request is bytes object, need to make string
                    reqdata = "\r\n\r\n".join(request.split("\r\n\r\n")[1:]).strip()
                    # We store the content-type of the request for verbose errors.
                    content_type = ""
                    # See if it's a json request
                    if 'Content-Type: application/json' in request:
                        content_type = "application/json"
                        reqdata = json.loads(reqdata)
                        params = createParameterDictionary(data['url'], reqdata, is_json=True)
                    elif 'Content-Type: application/xml' in request or 'Content-Type: text/xml' in request:
                        content_type = "application/xml"
                        params = createParameterDictionary(data['url'], reqdata, is_xml=True)
                    elif 'Content-Type: multipart/form-data' in request:
                        content_type = "multipart/form-data"
                        params = createParameterDictionary(data['url'], reqdata, is_formdata=True)
                    else:
                        content_type = "application/x-www-form-urlencoded"
                        # Some other mimetype we assume to be application/url-encoded
                        params = createParameterDictionary(data['url'], reqdata)
                except IndexError as e:
                    pass
                except Exception as e:
                    if verbose:
                        print("[!] Warning: Error occured while decoding {} request data:".format(content_type))
                        print("[!] \t{}".format(e))
                        print("[!] Request was: \n[-]\t{}".format(request.replace("\n","\n[!]\t")))
                        print()
                    request = ""
            domresults[path][method]['params'].update(params)
            domresults[path][method]['requests'].append(request)
        results[domain] = domresults
    return results

def createSQLMapRequest(request, insertion_point):
    """
    Given a decoded, plaintext request and a defined insertion point,
    create a request with an * inserted at point of insertion.

    Parameters:
        request(str)         : Raw HTTP request.
        insertion_point(int) : Index to inject the sqlmap insertion point.

    Returns:
        str: Raw HTTP request stitched together with
             the new * inserted at insertion_point
    """
    newreq = request[:insertion_point]
    if newreq[-1] != "*":
        # We've not added an insertion point before an
        newreq += "*"
        newreq += request[insertion_point:]
    else:
        newreq = request
    return newreq

def getSQLInsertionPoint(req, loc, key=None):
    """
    Find where to inject based on location. Looks
    for common terminators of parameters in various types
    of content-typed requests.

    Parameters:
        req(str): Raw HTTP request.
        loc(int): Integer of where to start search.
        key(str): Key of node to inject into. Required for xml request.

    Returns:
        (int or None, req) - Int is the index of the found terminator,
                     req is the new request with the added *
    """
    insertion_point = None
    if 'Content-Type: application/json' in req:
        # Looking for a different set of key markers in the request body.
        # JSON is separated by quotes and commas.
        if req.find('",', loc) != -1:
            # It's one parameter amongst many
            insertion_point = req.find('",', loc)
        elif req.find('"}', loc) != -1:
            # Do some more stuff
            insertion_point = req.find('"}', loc)
        elif req.find('"\r\n', loc) != -1:
            insertion_point = req.find('"\r\n', loc)
        elif req.find('"\n', loc) != -1:
            insertion_point = req.find('"\n', loc)
        else:
            pass
    elif 'Content-Type: application/xml' in req or 'Content-Type: text/xml' in req:
        """
        Two cases we need to cover.
        <root>
            val1
        </root>
        Or
        <root>val1</root>

        Cases are too complex, added new key to deal with it.
        """
        # if loc == -1:
        #     print("-1 location in xml!")
        # elif loc == len(req):
        #     print("loc == len(req)")
        try:
            diced = req.split("\r\n\r\n")
            reqdata = diced[1]
            soup = BeautifulSoup(reqdata, 'xml')
            if soup.find(key):
                # Valid key found in XML!
                if soup.find(key).string[-1] != "*":
                    # We haven't inserted a marker here yet, add
                    soup.find(key).string += "*"
                    insertion_point = True
                    diced[1] = str(soup)
                    req = "\r\n\r\n".join(diced)
        except Exception as e:
            pass
                    
    elif 'Content-Type: multipart/form-data' in req:
        # add insertion points for form data
        diced = req.split("\r\n\r\n")
        reqdata = "\r\n\r\n".join(diced[1:])
        lines = reqdata.split("\r\n")
        add_asterisk = False
        count = 0
        insertion_point = False
        for i in range(len(lines)):
            if add_asterisk:
                if count == 1:
                    if lines[i] and lines[i][-1] != "*":
                        lines[i] += "*"
                        insertion_point = True
                        add_asterisk = False
                        count = 0
                    else:
                        count = 0
                else:
                    count += 1
            elif 'name="{}"'.format(key) in lines[i]:
                add_asterisk = True
        if insertion_point:
            diced[1] = "\r\n".join(lines)
            req = "\r\n\r\n".join(diced[0:2])

    else:
        # Regular encoding
        if req.find("&",loc) != -1:
            # Somewhere in GET or POST body
            insertion_point = req.find("&", loc)
        elif req.find(" HTTP",loc) != -1:
            # End of GET query param
            insertion_point = req.find(" HTTP", loc)
        elif 'POST ' in req:
            # End of doc!
            insertion_point = len(req)
        else:
            pass
    if insertion_point and insertion_point is not True:
        req = createSQLMapRequest(req, insertion_point)
        # if "GET " in req:
    return (insertion_point, req)


def findSQLParams(params):
    """
    Find return a list of parameters that seem to match SQL syntax
    params is a dict.

    Parameters:
        params (dict): Dictionary contianing keys 'params' and 'requests'.
                       'params' key should contain set of unique values, while
                       'requests' key should contain a list of requests (decoded)
                       to interpret and return.
    Returns:
        Ex:
        {
        "key1": ("val1","val2"),
        "key2": ("val3","val4"),
        "sqlmap_requests": [
            "Raw request that contians SQLmap custom injection marker."
        ]
        }
    """
    sqlParams = {}
    
    for regex in compiledSql:
        for key, value_set in params['params'].items():
            keyMatch = False
            valMatch = False
            # If key looks suspicious
            if regex.match(key):
                # Debugging
                keyMatch = True
                # sqlParams.append(key)
            # If any parameter value looks suspicious
            elif any([regex.match(str(x)) for x in value_set]):
                # Debugging
                valMatch = True
                # sqlParams.append(key)
            if keyMatch or valMatch:
                if key not in sqlParams.keys():
                    sqlParams[key] = {
                        "values": set(),
                        "keyMatch": keyMatch,
                        "completed": False
                    }
                sqlParams[key]["values"].update(value_set)
                
    # Now create the sqlmap requests once all items are discovered
    sql_requests = set()
    incomplete_keys = list(sqlParams.keys())
    
    # Dictionary to keep track of which value sets have modified
    # requests already added and which do not
    tracking_dict = {}


    for req in params['requests']:
        add_req = False
        if all(y['completed'] for x, y in sqlParams.items()):
            # Done, completed all sqlmap requests!
            break
        else:
            for key, data in sqlParams.items():
                if data['completed']:
                    pass
                elif data['keyMatch']:
                    # Do the work.
                    if key in req:
                        # Found the parameter in the request!
                        loc = req.index(key)
                        insertion_point, req = getSQLInsertionPoint(req, loc, key=key)
                        if insertion_point:
                            add_req = True
                            data['completed'] = True
                else:
                    # Go through each value set not just keys
                    if key not in tracking_dict.keys():
                        tracking_dict[key] = set()
                    if tracking_dict[key] == data['values']:
                        # We're done!
                        data['completed'] = True
                        break
                    else:
                        for val in data['values']:
                            if tracking_dict[key] == data['values']:
                                # We've completed it!
                                data['completed'] = True
                                break
                            elif str(val) in req:
                                # We've found it!
                                loc = req.index(val)
                                insertion_point, req = getSQLInsertionPoint(req, loc, key=key)
                                if insertion_point:
                                    add_req = True
                                    tracking_dict[key].add(val)
        if add_req:
            sql_requests.add(req)

    results = {
        'params': sqlParams,
        'sqlmap_requests': sql_requests
    }    

    return results

def createResults(parsed_xml_results):
    """
    Take the results from parse_xml and create an actionable
    dictionary with data regarding the SQL requests.

    Parameters:
        parsed_xml_results(dict): Dictionary returned from the
                                  function parse_xml.

    Returns:
        dict

    Example return dictionary:

    {
        "google.com": {
            "/search": {
                "GET": {
                    "params"  : set('query','filter'),
                    "requests": set("GET /search?query=1*...", "GET /search?filter=2*...")
                }
                "POST": {
                    "params"  : set('param1', 'param2'),
                    "requests": set("POST /search...")
                }
            },
            "/login": {...}
        }
    }

    Note that "params" is the set of potentially vulnerable SQL parameters,
    and "requests" is the set of raw HTTP requests with SQLMap injection
    markers.
    """
    results = {}
    for domain, sitemap in parsed_xml_results.items():
        results[domain] = {}

        for path, methods in sitemap.items():
            for method, params in methods.items():
                # params has key 'params' and key 'requests'
                sqlData = findSQLParams(params)
                # counter = 0
                if sqlData['params']:
                    # Initialize results dictionary.
                    if path not in results[domain].keys():
                        results[domain][path] = {}
                    
                    if method not in results[domain][path].keys():
                        results[domain][path][method] = {'params': set(), 'requests': set()}

                    # Add paramters to dictionary at path->method->params
                    results[domain][path][method]['params'] = results[domain][path][method]['params'].union(sqlData['params'].keys())
                    results[domain][path][method]['requests'] = results[domain][path][method]['requests'].union(sqlData['sqlmap_requests'])
    return results

def main():
    """
    Function called when running from the command line.
    """
    banner = """
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

"""

    usage = """{}%prog -d example.com -f burpproxy.xml

SleuthQL is a script for automating the discovery of requests matching
SQL-like parameter names and values. When discovered, it will display
any matching parameters and paths that may be vulnerable to SQL injection.
It will also create a directory with SQLMap ready request files.

""".format(banner)
    parser = OptionParser(usage)
    parser.add_option('-d', '--domains', dest='domains', help="Comma separated list of domains to analyze. i.e.: google.com,mozilla.com,rhinosecuritylabs.com")
    parser.add_option('-f', '--xml', dest='proxy_xml', help='Burp proxy history xml export to parse. Must be base64 encoded.')
    parser.add_option('-v', '--verbose', dest='verbose', action="store_true", default=False, help='Show verbose errors that occur during parsing of the input XML.')    
    (options, args) = parser.parse_args()

    if not options.proxy_xml:
        print('Require Burp Proxy XML. Pass the -f or --xml to be passed on the command line.')
        print()
        print(parser.print_help())
        exit(1)

    if not options.domains:
        print('Require a comma separated list of domains. Pass the -d or --domains flag.')
        print()
        print(parser.print_help())
        exit(1)

    # Eventually add file permission checking here
    print(banner)
    f = open(options.proxy_xml, 'r')

    print("[+] Loading data from {}...".format(options.proxy_xml))
    soup = BeautifulSoup(f, 'xml')

    domains = [x.strip() for x in options.domains.split(',')]

    parsed_xml_results = parse_xml(soup, domains, verbose=options.verbose)
    results = createResults(parsed_xml_results)

    print("\nResults")
    print("-"*7)
    for domain, path_dict in results.items():
        try:
            mkdir(domain)
        except FileExistsError as e:
            pass
        print()
        print("-"*(len(domain)+4))
        print("| {} |".format(domain))
        print("-"*(len(domain)+4))
        for path, method_dict in path_dict.items():
            for method, data in method_dict.items():
                print("\t{} {}:".format(method, path))
                print("\t\t{}".format(",".join(data['params'])))
                counter = 0
                for request in data['requests']:
                    with open("{}/{}_{}_{}.txt".format(domain, method, path.replace("/","."), counter), 'w') as f:
                        f.write(request)
                    counter += 1

if __name__ == "__main__":
    import sys
    if sys.version_info[0] < 3:
        raise "This script must be ran under Python 3."
    main()
