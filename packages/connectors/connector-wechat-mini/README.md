# WeChat Mini Program connector

Configure the connector with `appId` and `appSecret`.

The `appId` must use the WeChat `wx` prefix followed by 16 lowercase hexadecimal characters. The
opaque `appSecret` is accepted only when it contains 16 to 128 ASCII alphanumeric characters;
whitespace and control characters are rejected before a provider request.

The connector exchanges the Mini Program code only at the fixed provider endpoint
`https://api.weixin.qq.com/sns/jscode2session`.

A non-empty UnionID is required. The response `session_key`, OpenID, and other provider response
identifiers are not retained in `rawData`; the required UnionID is used only as the Logto social
user ID.

Deployment invariant: because this connector has `platform: null`, `wechat-mini` must never be
enabled in Logto's hosted social target without an explicit `wechat-web` connector for the same
`wechat` target. The Box AI provisioner enforces `mini/native => web`; this connector package is
not directly exposed to end users.
