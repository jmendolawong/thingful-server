const express = require('express')
const AuthService = require('./auth-service')


const authRouter = express.Router()
const jsonParser = express.json()

authRouter
  .post('/login', jsonParser, (req, res, next) => {
    // Gets user_name and password from request body, assigns to loginUser
    const { user_name, password } = req.body
    const loginUser = { user_name, password }

    // Checks to make sure the values are not null for either keys, else error
    for (const [key, value] of Object.entries(loginUser))
      if (value == null)
        return res.status(400).json({
          error: `Missing '${key}' in request body`
        })

    // Use client provided user_name and cross check against user database
    AuthService.getUserWithUserName(
      req.app.get('db'),
      loginUser.user_name
    )

      // Check response data, dbUser, if null, throw error
      .then(dbUser => {
        if (!dbUser)
          return res.status(400).json({
            error: 'Incorrect user_name or password',
          })

        // Else true, compare client provided password (loginUser.password) with password in db (dbUser.password)
        // AuthService hashes loginUser.password and compares to hashed password in db
        return AuthService.comparePasswords(loginUser.password, dbUser.password)
          // If false, throw error
          .then(compareMatch => {
            if (!compareMatch)
              return res.status(400).json({
                error: 'Incorrect user_name or password',
              })

            // Subject = user_name in db, payload = id in db
            // Send client JWT
            const sub = dbUser.user_name
            const payload = { user_id: dbUser.id }
            res.send({
              authToken: AuthService.createJwt(sub, payload),
            })
          })
      })
      .catch(next)
  })

module.exports = authRouter