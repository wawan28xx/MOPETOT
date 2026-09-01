import hashlib
import hmac
import datetime

def generate_aws_sts_headers(access_key: str, secret_key: str, session_token: str = ""):
    method = 'POST'
    service = 'sts'
    host = 'sts.amazonaws.com'
    region = 'us-east-1'
    endpoint = 'https://sts.amazonaws.com/'
    
    request_parameters = 'Action=GetCallerIdentity&Version=2011-06-15'
    
    t = datetime.datetime.utcnow()
    amzdate = t.strftime('%Y%m%d%T')
    datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope
    
    canonical_uri = '/'
    canonical_querystring = ''
    canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'
    if session_token:
        canonical_headers += 'x-amz-security-token:' + session_token + '\n'
        signed_headers = 'host;x-amz-date;x-amz-security-token'
    else:
        signed_headers = 'host;x-amz-date'
        
    payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()
    
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
    
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' + amzdate + '\n' + credential_scope + '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    
    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
        
    kDate = sign(('AWS4' + secret_key).encode('utf-8'), datestamp)
    kRegion = sign(kDate, region)
    kService = sign(kRegion, service)
    kSigning = sign(kService, 'aws4_request')
    
    signature = hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    
    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
    
    headers = {
        'host': host,
        'x-amz-date': amzdate,
        'Authorization': authorization_header,
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8'
    }
    if session_token:
        headers['x-amz-security-token'] = session_token
        
    return endpoint, request_parameters, headers

print("AWS Signer test:")
ep, body, hdrs = generate_aws_sts_headers("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
print("Headers:", hdrs)
