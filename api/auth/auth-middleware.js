const { JWT_SECRET } = require("../secrets");
const jwt = require('jsonwebtoken');
const User = require('../users/users-model');

const restricted = (req, res, next) => {
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
  if (req.decodedJwt && req.decodedJwt.role_name === role_name) {
    next()
  } else {
    next({ status: 403, message: 'This is not for you' })
  }
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
