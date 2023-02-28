const { JWT_SECRET } = require("../secrets");
const jwt = require('jsonwebtoken');
const User = require('../users/users-model');

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
  const token = req.headers.authorization
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        next({ status: 401, message: `Token invalid` })
      } else {
        req.decodedJwt = decoded
        next()
      }
    })
  } else {
    next({ status: 401, message: 'Token required' })
  }
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
  console.log('passing through the only mw');
  next()
}


const checkUsernameExists = async (req, res, next) => {
  try {
    if (!req.body.username || !req.body.username) {
      next({ status: 401, message: 'Invalid credentials' });
    }
  
    const [user] = await User.findBy({ username: req.body.username });
  
    if (!user) {
      next({ status: 401, message: 'Invalid credentials' });
    } else {
      req.user = user;
      next();
    }
  } catch (err) {
    next(err);
  }
}


const validateRoleName = (req, res, next) => {
  if (!req.body.role_name || !req.body.role_name.trim()) {
    req.body.role_name = 'student'
    next()
  } else if (req.body.role_name.trim() === 'admin') {
    next({ status: 422, message: 'Role name can not be admin' })
  } else if (req.body.role_name.trim().length > 32) {
    next({ status: 422, message: 'Role name can not be longer than 32 chars' })
  } else {
    req.body.role_name = req.body.role_name.trim();
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
