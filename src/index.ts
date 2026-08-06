import {
  APIGatewayTokenAuthorizerEvent,
  APIGatewayAuthorizerResult,
} from "aws-lambda";
import { jwtVerify, createRemoteJWKSet } from "jose";

const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const COGNITO_USER_POOL_CLIENT_ID = process.env.COGNITO_USER_POOL_CLIENT_ID;

if (!COGNITO_USER_POOL_ID) {
  throw new Error("COGNITO_USER_POOL_ID is required");
}

if (!COGNITO_USER_POOL_CLIENT_ID) {
  throw new Error("COGNITO_USER_POOL_CLIENT_ID is required");
}

const JWKS = createRemoteJWKSet(
  new URL(
    `https://cognito-idp.us-west-2.amazonaws.com/${COGNITO_USER_POOL_ID}/.well-known/jwks.json`,
  ),
);

function hasScope(scope: string, required: string): boolean {
  return scope.split(" ").includes(required);
}

export async function handler(
  event: APIGatewayTokenAuthorizerEvent,
): Promise<APIGatewayAuthorizerResult> {
  const tokenHeader = event.authorizationToken?.trim();

  if (!tokenHeader?.startsWith("Bearer ")) {
    throw new Error("Unauthorized");
  }

  const token = tokenHeader.slice("Bearer ".length);

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      algorithms: ["RS256"],
      issuer: `https://cognito-idp.us-west-2.amazonaws.com/${COGNITO_USER_POOL_ID}`,
    });

    if (payload.token_use !== "access") {
      throw new Error("Not an access token!");
    }

    // Cognito access tokens use client_id (not aud) for the app client.
    if (payload.client_id !== COGNITO_USER_POOL_CLIENT_ID) {
      throw new Error("Invalid client!");
    }

    if (
      typeof payload.scope !== "string" ||
      !hasScope(payload.scope, "aws.cognito.signin.user.admin")
    ) {
      throw new Error("Insufficient permissions!");
    }

    const username =
      typeof payload.username === "string" ? payload.username : "unknown";

    return {
      principalId: payload.sub ?? "unknown",
      policyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Action: "execute-api:Invoke",
            Effect: "Allow",
            Resource: event.methodArn,
          },
        ],
      },
      context: {
        username,
        scope: payload.scope,
      },
    };
  } catch (err) {
    console.error("Token verification failed:", (err as Error).message);
    throw new Error("Unauthorized");
  }
}
