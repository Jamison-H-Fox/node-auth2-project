const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET, BCRYPT_ROUNDS } = require("../secrets"); // use this secret!
const User = require('../users/users-model');

router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;
  
  const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS)
  user.password = hash;

  User.add(user)
    .then(newUser => {
      res.status(201).json(newUser)
    })
    .catch(next)
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    let { username, password } = req.body;
    const user = await User.findBy({ username }).first();
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = buildToken(user);
      res.status(200).json({ message: `${user.username} is back!`, token });
    } else {
      next({ status: 401, message: 'Invalid Credentials' })
    }
  } catch (err){
    next(err)
  }
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
