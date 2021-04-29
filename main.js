const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const jwtDecode = require("jwt-decode");

function getCognitoUser({ Username, UserPoolId, ClientId }) {
  return new AmazonCognitoIdentity.CognitoUser({
    Username,
    Pool: new AmazonCognitoIdentity.CognitoUserPool({
      UserPoolId,
      ClientId,
    }),
  });
}

/**
 *
 * @returns {Promise<AmazonCognitoIdentity.CognitoUserSession>}
 */
async function getUserSession({ Username, Password, UserPoolId, ClientId }) {
  return new Promise((accept, reject) => {
    getCognitoUser({ Username, UserPoolId, ClientId }).authenticateUser(
      new AmazonCognitoIdentity.AuthenticationDetails({
        Username,
        Password,
      }),
      {
        onSuccess: accept,
        onFailure: reject,
      }
    );
  });
}

async function refreshUserSession({
  Username,
  UserPoolId,
  ClientId,
  RefreshToken,
}) {
  return new Promise((accept, reject) => {
    getCognitoUser({ Username, UserPoolId, ClientId }).refreshSession(
      new AmazonCognitoIdentity.CognitoRefreshToken({
        RefreshToken,
      }),
      (err, session) => {
        if (err) {
          reject(err);
        } else {
          accept(session);
        }
      }
    );
  });
}

function isTokenExpired(token) {
  const { exp } = jwtDecode(token);
  return exp < new Date().getTime() / 1000;
}

function getCacheKey({ Username, UserPoolId, ClientId }) {
  return JSON.stringify([Username, UserPoolId, ClientId]);
}

async function restoreCredentials(store, { Username, UserPoolId, ClientId }) {
  const cachedCredentials = await store.getItem(
    getCacheKey({ Username, UserPoolId, ClientId })
  );
  try {
    const { accessToken, refreshToken } = JSON.parse(cachedCredentials);
    if (!isTokenExpired(accessToken)) {
      return { accessToken, refreshToken };
    } else if (!isTokenExpired(refreshToken)) {
      // should refresh the session, but for now just re-authenticate
      return null;
    } else {
      return null;
    }
  } catch {
    return null;
  }
}

async function persistCredentials(
  store,
  { Username, UserPoolId, ClientId },
  { accessToken, refreshToken }
) {
  await store.setItem(
    getCacheKey({ Username, UserPoolId, ClientId }),
    JSON.stringify({ accessToken, refreshToken })
  );
}

async function getNewCredentials({ Username, Password, UserPoolId, ClientId }) {
  const session = await getUserSession({
    Username,
    Password,
    UserPoolId,
    ClientId,
  });
  return {
    accessToken: session.getAccessToken().getJwtToken(),
    refreshToken: session.getRefreshToken(),
  };
}

const run = async ({ store }, Username, Password, UserPoolId, ClientId) => {
  const credentials = await restoreCredentials(store, {
    Username,
    UserPoolId,
    ClientId,
  });
  if (credentials !== null) {
    return credentials.accessToken;
  } else {
    const newCredentials = await getNewCredentials({
      Username,
      Password,
      UserPoolId,
      ClientId,
    });
    await persistCredentials(
      store,
      { Username, UserPoolId, ClientId },
      newCredentials
    );
    return newCredentials.accessToken;
  }
};

module.exports.templateTags = [
  {
    name: "InsomniaCognitoPasswordToken",
    displayName: "Insomnia cognito password token",
    description:
      "Get an access token from AWS Cognito using password-based authentication.",
    args: [
      {
        displayName: "Username",
        type: "string",
        validate: (arg) => (arg ? "" : "Required"),
      },
      {
        displayName: "Password",
        type: "string",
        validate: (arg) => (arg ? "" : "Required"),
      },
      {
        displayName: "UserPoolId",
        type: "string",
        validate: (arg) => (arg ? "" : "Required"),
      },
      {
        displayName: "ClientId",
        type: "string",
        validate: (arg) => (arg ? "" : "Required"),
      },
    ],
    run,
  },
];
