# WeChat Official Account H5 connector

Configure the connector with the AppID and AppSecret for a WeChat Official Account that has web
page authorization enabled.

The AppID must use the WeChat `wx` prefix followed by 16 lowercase hexadecimal characters. The
opaque AppSecret accepts only 16 to 128 ASCII alphanumeric characters. The connector always uses
the fixed `snsapi_userinfo` scope and exchanges credentials only with the documented WeChat OAuth
and user-info endpoints.

The authorization callback must be an HTTPS URL with a host and a non-root path. Provider requests
have a five-second timeout, do not retry, redirect, or decompress responses, and reject responses
larger than 16 KiB.

A non-empty UnionID is required. Access tokens, OpenID, and raw provider data are never returned to
Logto as user profile data.
