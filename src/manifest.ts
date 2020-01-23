import { verify } from "jsonwebtoken";

const name: string = "extract-jwt-claim";

const schema: any = {
  $id: 'https://cloud.novutek.com/schemas/policies/extract-jwt-claim.json',
  type: 'object',
  properties: {
    secretOrPublicKey: {
      type: "object",
      description: "Secret or public key to validate the JWT"
    },
    verifyOptions: {
      type: "object",
      description: "Verify options of JWT (see jsonwebtoken library)"
    },
    payload: {
      type: "string",
      description: "Claim name which contains payload to place it on request object"
    }
  }, 
  required: ["secretOrPublicKey"]
};

const policy = (params: any) => {
  return (req: any, res: any, next: any) => {
    if(!req.headers || !req.headers.authorization) {
      return res.status(401).send({ error: "MISSING_ACCESS_TOKEN_ERROR" });
    }
    if(!req.headers.authorization.startsWith("Bearer ")) {
        return res.status(401).send({ error: "SCHEMA_AUTHORIZATION_NOT_SUPPORTED_ERROR" });
    }
    const token: string = req.headers.authorization.split(" ")[1];

    try {
        const json: any = verify(token, params.secretOrPublicKey, params.verifyOptions);
        console.log({ jwt: json });
        req.subject = json.sub;
        if(params.payload) {
          req[params.payload] = json[params.payload] || null;
        }
        next();
    } catch(error) {
        // console.log(error);
        // name: 'JsonWebTokenError', message: 'invalid algorithm'
        if(error && error.name && error.name === "TokenExpiredError") {
            return res.status(401).send({ error: "TOKEN_EXPIRED_ERROR" });
        }
        res.status(400).send({ error: "ACCESS_TOKEN_VERIFICATION_ERROR" });
    }
  };
};

const plugin: any = {
  version: "0.1.0",
  policies: ["extract-jwt-claim"],
  init: (context: any) => {
    context.registerPolicy({ name, schema, policy })
  }
};

exports.default = plugin;