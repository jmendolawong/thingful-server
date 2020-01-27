const bcrypt = require('bcryptjs')
const AuthService = require('../auth/auth-service')


function requireAuth(req, res, next) {
  let basicToken

  //get authToken from request header, else set to blank ''
  const authToken = req.get('Authorization') || ''

  //if the authToken (lowercased) doesn't start with 'basic ', return error
  if (!authToken.toLowerCase().startsWith('basic ')) {
    return res.status(401).json({ error: 'Missing basic token' })
  } else { //split authToken and assign it to basicToken
    basicToken = authToken.slice('basic '.length, authToken.length)
  }

  //split basicToken to user_name and password via buffer
  const [tokenUserName, tokenPassword] = AuthService.parseBasicToken(basicToken)

  //Check if there is a user_name or password missing - error
  if (!tokenUserName || !tokenPassword) {
    return res.status(401).json({ error: 'Unauthorized request' })
  }

  //Check if the tokenUsername against the database of users
  //If exists, check user.password against tokenPassword
  AuthService.getUserWithUserName(
    req.app.get('db'),
    tokenUserName)
    .then(user => {
      if (!user) {
        return res.status(401).json({ error: 'Unauthorized request' })
      }
      return AuthService.comparePasswords(tokenPassword, user.password)
        .then(passwordsMatch => {
          if (!passwordsMatch) {
            return res.status(401).json({ error: 'Unauthorized request' })
          }
          req.user = user
          next()
        })
    })
    .catch(next)
}

module.exports = {
  requireAuth,
}