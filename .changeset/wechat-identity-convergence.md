---
"@logto/core": patch
"@logto/connector-kit": patch
"@logto/phrases": patch
"@logto/connector-wechat-web": major
"@logto/connector-wechat-native": major
"@logto/connector-wechat-mini": minor
"@logto/experience": patch
---

require strict UnionID identities and redact provider data for WeChat Web and Native, add a Mini Program connector, and make exact social-binding retries idempotent

WeChat Web and Native no longer fall back to OpenID when `unionid` is missing and now return an empty `SocialUserInfo.rawData`. Before upgrading, configure each app under WeChat Open Platform so responses include `unionid`, and stop consuming provider response fields from `rawData`.

The hosted sign-in experience also keeps Mini Program connectors out of Web and Native platform lists and removes infrastructure branding.
