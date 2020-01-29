const REGEX_PASSWORD_COMPLEXITY = /(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&])[\S]+/
const xss = require('xss')
const bcrypt = require('bcryptjs')

const UsersService = {
  validatePassword(password) {
    if (password.length < 8) {
      return `Password must be longer than 8 characters`
    }
    if (password.length > 72) {
      return `Password must be less than 72 characters`
    }

    if (password.startsWith(' ') || password.endsWith(' ')) {
      return `Password cannot begin or end with spaces`
    }

    if (!REGEX_PASSWORD_COMPLEXITY.test(password)) {
      return `Password must have 1 uppercase, lowercase, number and special character`
    }
    return null
  },

  hasUserWithUserName(db, user_name) {
    return db('thingful_users')
      .where({ user_name })
      .first()
      .then(user => !!user)
  },

  insertUser(db, newUser) {
    return db
      .insert(newUser)
      .into('thingful_users')
      .returning('*')
      .then(([user]) => user)
  },

  serializeUser(user) {
    return {
      id: user.id,
      user_name: xss(user.user_name),
      full_name: xss(user.full_name),
      nickname: xss(user.nickname),
      date_created: new Date(user.date_created)
    }
  },

  hashPassword(password) {
    return bcrypt.hash(password, 12)
  }
}

module.exports = UsersService
