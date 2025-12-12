#!/usr/bin/env python3
import json
import time
import argparse
from pathlib import Path

from authlib.jose import jwt, JsonWebKey
from cryptography.hazmat.primitives import serialization
from jwskate import JweCompact


# Default values (can be overridden by command line arguments)
KID_SIGNING = (
    "<KID_SIGNING_VALUE>"
)
KID_ENCRYPTION = (
    "KID_ENCRYPTION_VALUE>"
)

DEFAULT_CLIENT_ID = "iLIfODggMfBFgTtX_0inr5uLIQoa"
DEFAULT_REDIRECT_URI = "https://localexample.com"
DEFAULT_ISSUER = "https://localhost:9443/oauth2/token"

CLIENT_PRIVATE_KEY_PATH = (
    "<PRIVATE_KEY_PATH>"
)
AS_PUBLIC_KEY_PATH = (
    "<PUBLIC_KEY_PATH>"
)

DEFAULT_SIGNING_ALG = "PS256"
DEFAULT_KEY_MGMT_ALG = "RSA-OAEP-384"
DEFAULT_CONTENT_ENC_ALG = "A192CBC-HS384"


def load_private_pem(path: str) -> bytes:
    return Path(path).read_bytes()


def load_public_key_obj(path: str):
    pem = Path(path).read_bytes()
    return serialization.load_pem_public_key(pem)


def build_request_object_claims(
        client_id: str,
        redirect_uri: str,
        request_object_aud: str,
) -> dict:
    now = int(time.time())
    return {
        "iss": client_id,
        "aud": request_object_aud,
        "response_type": "code id_token",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid accounts",
        "state": "xyz123",
        "nonce": "n-0S6_WzA2Mj",
        "max_age": 600,
        "exp": now + 600,
        "iat": now,
        "id_token": {
            "acr": {
                "essential": True,
                "values": ["urn:openbanking:psd2:sca"],
            }
        },
        "claims": {
            "id_token": {
                "sub": {"essential": True}
            }
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a signed and encrypted FAPI request object "
            "for use as the `request` parameter."
        )
    )

    parser.add_argument(
        "--kid-signing",
        default=KID_SIGNING,
        help="Key ID for the signing key (JWS header kid).",
    )
    parser.add_argument(
        "--kid-encryption",
        default=KID_ENCRYPTION,
        help="Key ID for the encryption key (not currently used in headers).",
    )
    parser.add_argument(
        "--client-id",
        default=DEFAULT_CLIENT_ID,
        help="OAuth client identifier.",
    )
    parser.add_argument(
        "--redirect-uri",
        default=DEFAULT_REDIRECT_URI,
        help="Redirect URI to include in the request object.",
    )
    parser.add_argument(
        "--issuer",
        default=DEFAULT_ISSUER,
        help="Issuer value (usually token endpoint) used in iss and default aud.",
    )
    parser.add_argument(
        "--request-object-aud",
        default=None,
        help=(
            "Audience for the request object. "
            "If not set, the value of --issuer is used."
        ),
    )
    parser.add_argument(
        "--client-private-key-path",
        default=CLIENT_PRIVATE_KEY_PATH,
        help="Path to client private key PEM used for signing.",
    )
    parser.add_argument(
        "--as-public-key-path",
        default=AS_PUBLIC_KEY_PATH,
        help="Path to authorisation server public key PEM used for encryption.",
    )
    parser.add_argument(
        "--signing-alg",
        default=DEFAULT_SIGNING_ALG,
        help="JWS signing algorithm (for example PS256).",
    )
    parser.add_argument(
        "--key-mgmt-alg",
        default=DEFAULT_KEY_MGMT_ALG,
        help="JWE key management algorithm (for example RSA-OAEP-384).",
    )
    parser.add_argument(
        "--content-enc-alg",
        default=DEFAULT_CONTENT_ENC_ALG,
        help="JWE content encryption algorithm (for example A192CBC-HS384).",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    request_object_aud = args.request_object_aud or args.issuer

    client_private_pem = load_private_pem(args.client_private_key_path)
    as_public_key = load_public_key_obj(args.as_public_key_path)

    signing_key = JsonWebKey.import_key(client_private_pem)
    claims = build_request_object_claims(
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        request_object_aud=request_object_aud,
    )

    signing_header = {
        "alg": args.signing_alg,
        "typ": "oauth-authz-req+jwt",
        "kid": args.kid_signing,
    }

    signed_request_object = jwt.encode(
        header=signing_header,
        payload=claims,
        key=signing_key,
    )

    if isinstance(signed_request_object, bytes):
        signed_bytes = signed_request_object
        signed_str = signed_request_object.decode("utf8")
    else:
        signed_bytes = signed_request_object.encode("utf8")
        signed_str = signed_request_object

    encrypted_request_object = JweCompact.encrypt(
        signed_bytes,
        key=as_public_key,
        alg=args.key_mgmt_alg,
        enc=args.content_enc_alg,
    )

    print("Signed request object (JWS):")
    print(signed_str)
    print()
    print(
        "Encrypted request object "
        f"(JWE, alg={args.key_mgmt_alg}, enc={args.content_enc_alg}):"
    )
    print(str(encrypted_request_object))
    print()
    print("Use this as the request parameter:")
    print("request=" + str(encrypted_request_object))


if __name__ == "__main__":
    main()