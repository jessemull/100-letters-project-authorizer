require("dotenv").config();
const {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
} = require("@aws-sdk/client-cognito-identity-provider");

const userPoolWebClientId = process.env.COGNITO_USER_POOL_CLIENT_ID;
const username = process.env.COGNITO_USER_POOL_USERNAME;
const password = process.env.COGNITO_USER_POOL_PASSWORD;

if (!userPoolWebClientId || !username || !password) {
  console.error(
    "COGNITO_USER_POOL_CLIENT_ID, COGNITO_USER_POOL_USERNAME, and COGNITO_USER_POOL_PASSWORD are required",
  );
  process.exit(1);
}

const client = new CognitoIdentityProviderClient({
  region: "us-west-2",
});

async function authenticateUser() {
  const params = {
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: userPoolWebClientId,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
    },
  };

  const command = new InitiateAuthCommand(params);
  const response = await client.send(command);
  const accessToken = response.AuthenticationResult?.AccessToken;

  if (!accessToken) {
    throw new Error("Cognito did not return an AccessToken");
  }

  console.log("Access Token:");
  console.log(accessToken);
}

authenticateUser().catch((error) => {
  console.error("Error authenticating user:", error);
  process.exitCode = 1;
});
