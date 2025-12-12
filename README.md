# OAuth2 FAPI Request Object Generator
This tool generates a fully signed and encrypted OAuth 2.0 or OpenID Connect **FAPI compliant Request Object**. It first produces a JWS using the client’s private key and then encrypts it into a compact JWE using the authorisation server’s public key. The resulting encrypted payload can be passed as the `request` parameter in an OAuth 2.0 Authorisation Request.

## Features
- Creates FAPI aligned request objects  
- Signs request objects using PS256  
- Encrypts signed request objects using RSA OAEP 384 and A192CBC HS384  
- Outputs both the signed JWS and encrypted JWE  
- Includes all mandatory FAPI claims (iss, aud, nonce, max_age etc.)  
- Ideal for testing and validating FAPI flows with WSO2 Identity Server  

## Requirements
- Python 3.8 or above  
- authlib  
- jwskate  
- cryptography  

Install requirements:
```
pip install authlib jwskate cryptography
```
## Configuration
The following values must be provided or adjusted in the script:
- Client private key path (PEM)  
- Authorisation server public encryption key path (PEM)  
- Client ID  
- Redirect URI  
- KIDs for signing and encryption  
- Token endpoint URL (audience for the request object)  
- Selected signing and encryption algorithms  

## What the Script Does
1. Loads the client’s private key  
2. Loads the AS public encryption key  
3. Builds a compliant request claim set  
4. Signs the claims into a JWS using PS256  
5. Encrypts the JWS into a compact JWE using RSA OAEP 384 and A192CBC HS384  
6. Prints:  
   - The signed request object (JWS)  
   - The encrypted request object (JWE)  
   - The full `request=` parameter ready to use in the Authorisation Request  

## Usage
Run the script as:
```
python3 fapi_request_object_generator.py
```
The output includes:
- Signed request object  
- Encrypted request object  
- A ready-to-use `request=<encrypted_value>` string  

Example Authorisation Request:
```
https://localhost:9443/oauth2/authorize?client_id=<CLIENT_ID>&request=<ENCRYPTED_REQUEST_OBJECT>
```
