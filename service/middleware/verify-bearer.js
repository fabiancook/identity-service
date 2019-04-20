import JSONWebToken from "jsonwebtoken";
import bearerToken from "express-bearer-token";

async function verify(request, response, next) {
	if (!request.token) {
    // No token, no pass
  	return response.sendStatus(401);
  }
  // Decode our token so we can 
  const decoded = JSONWebToken.decode(request.token, { complete: true });
  if (!decoded.header.kid) {
    // No kid, no pass, we didn't generate this
  	return response.sendStatus(401);
  }
  const store = request.app.locals.store;
  const keyInformation = await store.get(`jwt-key:${decoded.header.kid}`)
  	.then(value => JSON.parse(value))
  	.catch(() => undefined);
  if (!(keyInformation && keyInformation.algorithm && keyInformation.publicKey)) {
   	// No key information to compare to
  	return response.sendStatus(401);
  }
  const verified = await new Promise(
   	resolve => JSONWebToken.verify(
   		request.token,
      keyInformation.publicKey,
      {
        algorithms: [
          // Only allow the one that was stored with the key 
          keyInformation.algorithm
        ]
      },
      (error, verified) => resolve(error ? undefined : verified)
    )
  );
  if (!verified) {
   	// Not valid 
  	return response.sendStatus(401);
  }
  // Add our identity to the request, use `user` here as thats pretty standard
  request.user = {
    id: verified.sub
  };
  // Ready to rol;
  next(undefined);
}

function handler(request, response, next) {
  verify(request, response, next)
  	.catch(next);
}

export default [
  bearerToken(),
  verify
];