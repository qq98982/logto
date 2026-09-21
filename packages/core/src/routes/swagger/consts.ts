import { managementApiResourceIndicator } from '@logto/core-kit';

export const managementApiAuthDescription = `Aster Management API is a comprehensive set of REST APIs that gives you full control over Aster to suit your product needs and tech stack. To see the full guide on Management API interactions, visit [Interact with Management API](https://docs.logto.io/docs/recipes/interact-with-management-api/).

### Get started

The API follows the same authentication principles as other API resources in Aster, with some slight differences. To use Aster Management API:

1. A machine-to-machine (M2M) application needs to be created.
2. A machine-to-machine (M2M) role with Management API permission \`all\` needs to be assigned to the application.

Once you have them set up, you can use the \`client_credentials\` grant type to fetch an access token and use it to authenticate your requests to the Aster Management API.

### Fetch an access token

To fetch an access token, you need to make a \`POST\` request to the \`/oidc/token\` endpoint of your Aster tenant.

For hosted users, the base URL is your tenant endpoint, i.e. \`https://[tenant-id].logto.app\`. The tenant ID can be found in the following places:

- The first path segment of the URL when you are signed in to the hosted Console. For example, if the URL is \`https://cloud.logto.io/foo/get-started\`, the tenant ID is \`foo\`.
- In the "Settings" tab of the Console.

The default tenant uses \`${managementApiResourceIndicator}\`. Non-default tenants use \`${managementApiResourceIndicator}:<encoded-tenant-id>\`, where \`<encoded-tenant-id>\` is the tenant ID encoded with \`encodeURIComponent\`.

The request should follow the OAuth 2.0 [client credentials](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) grant type. Here is a non-normative example of how to fetch an access token:

\`\`\`bash
curl --location \\
  --request POST 'https://[tenant-id].logto.app/oidc/token' \\
  --header 'Content-Type: application/x-www-form-urlencoded' \\
  --data-urlencode 'grant_type=client_credentials' \\
  --data-urlencode 'client_id=[app-id]' \\
  --data-urlencode 'client_secret=[app-secret]' \\
  --data-urlencode 'resource=[management-api-resource]' \\
  --data-urlencode 'scope=all'
\`\`\`

Replace \`[tenant-id]\`, \`[management-api-resource]\`, \`[app-id]\`, and \`[app-secret]\` with your Aster tenant ID, its Management API resource indicator, application ID, and application secret, respectively.

The response will be like:

\`\`\`json
{
  "access_token": "eyJhbG...2g", // Use this value for accessing the Aster Management API
  "expires_in": 3600, // Token expiration in seconds
  "token_type": "Bearer", // Token type for your request when using the access token
  "scope": "all" // Scope \`all\` for Aster Management API
}
\`\`\`

### Use the access token

Once you have the access token, you can use it to authenticate your requests to the Aster Management API. The access token should be included in the \`Authorization\` header of your requests with the \`Bearer\` authentication scheme.

Here is an example of how to list the first page of users in your Aster tenant:

\`\`\`bash
curl --location \\
  --request GET 'https://[tenant-id].logto.app/api/users' \\
  --header 'Authorization: Bearer eyJhbG...2g'
\`\`\`

Replace \`[tenant-id]\` with your Aster tenant ID and \`eyJhbG...2g\` with the access token you fetched earlier.`;

export const userApiAuthDescription = `Logto User API is a set of REST APIs that gives the end user the ability to manage their own profile and perform verifications.

To use this API, you need to have an openid access token with empty audience and required scopes.
`;
