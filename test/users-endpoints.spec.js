const knex = require('knex')
const bcrypt = require('bcryptjs')
const app = require('../src/app')
const helpers = require('./test-helpers')


describe.only('Users Endpoints', function () {
  let db

  const { testUsers } = helpers.makeThingsFixtures()
  const testUser = testUsers[0]

  before('make knex instance', () => {
    db = knex({
      client: 'pg',
      connection: process.env.TEST_DB_URL,
    })
    app.set('db', db)
  })

  after('disconnect from db', () => db.destroy())

  before('cleanup', () => helpers.cleanTables(db))

  afterEach('cleanup', () => helpers.cleanTables(db))

  describe(`POST /api/users`, () => {
    context(`User Validation`, () => {
      beforeEach('insert users', () =>
        helpers.seedUsers(
          db,
          testUsers,
        )
      )

      const requiredFields = ['user_name', 'password', 'full_name']

      requiredFields.forEach(field => {
        const registerAttemptBody = {
          user_name: 'test user_name',
          password: 'test password',
          full_name: 'test full_name',
          nickname: 'test nickname',
        }

        it(`responds with 400 required error when '${field}' is missing`, () => {
          delete registerAttemptBody[field]

          return supertest(app)
            .post('/api/users')
            .send(registerAttemptBody)
            .expect(400, {
              error: `Missing '${field}' in request body`,
            })
        })
      })

      it(`responds 400 when password is less than 8 characters`, () => {
        const userShortPassword = {
          user_name: 'test_user',
          password: 'short',
          full_name: 'test_full_name',
        }

        return supertest(app)
          .post('/api/users')
          .send(userShortPassword)
          .expect(400, {
            error: `Password must be longer than 8 characters`,
          })
      })

      it(`responds 400 when password is greater than 72 characters`, () => {
        const userLongPassword = {
          user_name: 'test_user',
          password: '1'.repeat(73),
          full_name: 'test_full_name',
        }

        return supertest(app)
          .post('/api/users')
          .send(userLongPassword)
          .expect(400, {
            error: `Password must be less than 72 characters`,
          })
      })

      it(`responds 400 when password begins with space`, () => {
        const userPasswStartsWithSpace = {
          user_name: 'test_user',
          password: ' 1234567',
          full_name: 'test_full_name',
        }

        return supertest(app)
          .post('/api/users')
          .send(userPasswStartsWithSpace)
          .expect(400, {
            error: `Password cannot begin or end with spaces`,
          })
      })

      it(`responds 400 when password ends with space`, () => {
        const userPasswEndsWithSpace = {
          user_name: 'test_user',
          password: '1234567 ',
          full_name: 'test_full_name',
        }

        return supertest(app)
          .post('/api/users')
          .send(userPasswEndsWithSpace)
          .expect(400, {
            error: `Password cannot begin or end with spaces`,
          })
      })

      it(`responds 400 when password isn't complex enough`, () => {
        const userSimplePassword = {
          user_name: 'test_user',
          password: '12345678',
          full_name: 'test_full_name',
        }

        return supertest(app)
          .post('/api/users')
          .send(userSimplePassword)
          .expect(400, {
            error: `Password must have 1 uppercase, lowercase, number and special character`,
          })
      })

      it(`responds 400 'Username already taken' when registering same user_name`, () => {
        const repeatUser = {
          user_name: testUser.user_name,
          password: '!!22AABbb',
          full_name: 'test_full_name',
        }

        return supertest(app)
          .post('/api/users')
          .send(repeatUser)
          .expect(400, {
            error: `Username already taken`
          })
      })

    })

    context(`Happy Path`, () => {
      it(`responds 201, serialized user, storing bcrypted password`, () => {
        
        const newUser = {
          user_name: 'user_name',
          password: '!!11AAaaa',
          full_name: 'full_name'
        }

        return supertest(app)
          .post('/api/users')
          .send(newUser)
          .expect(201)
          .expect(res => {
            expect(res.body).to.have.property('id')
            expect(res.body.user_name).to.eql(newUser.user_name)
            expect(res.body.full_name).to.eql(newUser.full_name)
            expect(res.body.nickname).to.eql('')
            expect(res.body).to.not.have.property('password')
            expect(res.headers.location).to.eql(`/api/users/${res.body.id}`)
            const expectedDate = new Date().toLocaleString('en', { timeZone: 'UTC' })
            const actualDate = new Date(res.body.date_created).toLocaleString()
            expect(actualDate).to.eql(expectedDate)
          })
          .expect(res => {
            db
              .select('*')
              .from('thingful_users')
              .where({ id: res.body.id })
              .first()
              .then(row => {
                expect(row.user_name).to.eql(newUser.user_name)
                expect(row.full_name).to.eql(newUser.full_name)
                expect(row.nickname).to.eql(null)
                const expectedDate = new Date().toLocaleString('en', { timeZone: 'UTC' })
                const actualDate = new Date(row.date_created).toLocaleString()
                expect(actualDate).to.eql(expectedDate)

                return bcrypt.compare(newUser.password, row.password)
              })
              .then(comparePasswords => {
                expect(comparePasswords).to.be.true
              })
          })
      })

    })
  })
})