import type { APIGatewayTokenAuthorizerEvent } from "aws-lambda";
import { handler } from "./index";
import { jwtVerify } from "jose";

process.env.COGNITO_USER_POOL_ID = "us-west-2_fakePool";

jest.mock("jose", () => {
  return {
    jwtVerify: jest.fn(),
    createRemoteJWKSet: jest.fn().mockReturnValue("mockJWKS"),
  };
});

const mockedJwtVerify = jwtVerify as jest.Mock;

const baseEvent = {
  type: "TOKEN",
  authorizationToken: "Bearer fake.token.value",
  methodArn:
    "arn:aws:execute-api:region:account-id:api-id/stage/method/resource-path",
} satisfies APIGatewayTokenAuthorizerEvent;

describe("handler", () => {
  beforeEach(() => {});

  let consoleErrorSpy: jest.SpyInstance;

  beforeAll(() => {
    consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    jest.clearAllMocks();
  });

  afterAll(() => {
    consoleErrorSpy.mockRestore();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("throws if no Authorization header", async () => {
    await expect(
      handler({ ...baseEvent, authorizationToken: "" }),
    ).rejects.toThrow("No bearer token!");
  });

  it("throws if Authorization header doesn't start with Bearer", async () => {
    await expect(
      handler({ ...baseEvent, authorizationToken: "Token abc" }),
    ).rejects.toThrow("No bearer token!");
  });

  it("throws if jwtVerify throws (invalid token)", async () => {
    mockedJwtVerify.mockRejectedValueOnce(new Error("Invalid token"));
    await expect(handler(baseEvent)).rejects.toThrow("Unauthorized");
  });

  it("throws if token is not an access token", async () => {
    mockedJwtVerify.mockResolvedValueOnce({
      payload: {
        token_use: "id",
        sub: "user123",
        username: "testuser",
        scope: "aws.cognito.signin.user.admin",
      },
    });
    await expect(handler(baseEvent)).rejects.toThrow("Unauthorized");
  });

  it("throws if scope is missing", async () => {
    mockedJwtVerify.mockResolvedValueOnce({
      payload: {
        token_use: "access",
        sub: "user123",
        username: "testuser",
      },
    });
    await expect(handler(baseEvent)).rejects.toThrow("Unauthorized");
  });

  it("throws if scope does not contain required permission", async () => {
    mockedJwtVerify.mockResolvedValueOnce({
      payload: {
        token_use: "access",
        sub: "user123",
        username: "testuser",
        scope: "read write",
      },
    });
    await expect(handler(baseEvent)).rejects.toThrow("Unauthorized");
  });

  it("returns success for valid token", async () => {
    mockedJwtVerify.mockResolvedValueOnce({
      payload: {
        token_use: "access",
        sub: "abc123",
        username: "johndoe",
        scope: "aws.cognito.signin.user.admin other.scope",
      },
    });

    const result = await handler(baseEvent);

    expect(result).toEqual({
      principalId: "abc123",
      policyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Action: "execute-api:Invoke",
            Effect: "Allow",
            Resource: baseEvent.methodArn,
          },
        ],
      },
      context: {
        username: "johndoe",
        scope: "aws.cognito.signin.user.admin other.scope",
      },
    });
  });

  it("uses fallback values if sub or username is missing", async () => {
    mockedJwtVerify.mockResolvedValueOnce({
      payload: {
        token_use: "access",
        scope: "aws.cognito.signin.user.admin",
      },
    });

    const result = await handler(baseEvent);

    expect(result.principalId).toBe("unknown");
    expect(result?.context?.username).toBe("unknown");
  });

  it("throws if authorizationToken is undefined", async () => {
    await expect(
      handler({
        ...baseEvent,
        authorizationToken: undefined as unknown as string,
      }),
    ).rejects.toThrow("No bearer token!");
  });

  it("throws if authorizationToken is only whitespace", async () => {
    await expect(
      handler({ ...baseEvent, authorizationToken: "   " }),
    ).rejects.toThrow("No bearer token!");
  });
});
