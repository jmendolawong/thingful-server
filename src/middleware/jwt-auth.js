const AuthService = require('../auth/auth-service')

function requireAuth(req, res, next) {

  // Get authToken from the header 'Authorization'
  const authToken = req.get('Authorization') || ''
  let bearerToken

  // Check that it has a bearer token, else error
  // If true, extract the token by slicing out 'bearer '
  if (!authToken.toLowerCase().startsWith('bearer ')) {
    return res.status(401).json({ error: 'Missing bearer token' })
  } else {
    bearerToken = authToken.slice(7, authToken.length)
  }

  // verify bearer token lines up with database, else error
  try {
    // Gather payload from verified bearer token
    const payload = AuthService.verifyJwt(bearerToken)

    // Query db for user_name matching payload.sub
    AuthService.getUserWithUserName(
      req.app.get('db'),
      payload.sub,
    )
      // Get user and if null, error
      .then(user => {
        if (!user)
          return res.status(401).json({ error: `Unauthorized request` })

        // Assign req.user = user in db
        req.user = user
        next()
      })
      .catch(err => {
        console.log(err)
        next(err)
      })

  } catch (error) {
    return res.status(401).json({ error: `Unauthorized request` })
  }
}

module.exports = {
  requireAuth,
}
