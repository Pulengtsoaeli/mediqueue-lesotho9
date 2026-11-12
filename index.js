
import dotenv from 'dotenv'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import express from 'express'
import cors from 'cors'
import mysql from 'mysql2/promise'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { randomBytes } from 'node:crypto'

// ========================================
// LOAD ENVIRONMENT VARIABLES
// ========================================

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

dotenv.config({
  path: path.resolve(__dirname, '../.env'),
  override: true
})

console.log('Loaded DB_USER:', process.env.DB_USER || '(missing)')
console.log('Loaded DB_NAME:', process.env.DB_NAME || '(missing)')

const app = express()

// ========================================
// CORS CONFIGURATION
// ========================================

const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5175',
  'http://localhost:5176',
  'http://localhost:5177',
  'http://localhost:5178',
  'http://localhost:5179',

  'http://127.0.0.1:5173',
  'http://127.0.0.1:5175',
  'http://127.0.0.1:5176',
  'http://127.0.0.1:5177',
  'http://127.0.0.1:5178',
  'http://127.0.0.1:5179'
]

if (process.env.CLIENT_ORIGIN) {
  allowedOrigins.push(process.env.CLIENT_ORIGIN)
}

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true)
    }

    return callback(new Error(`Not allowed by CORS: ${origin}`))
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204
}))

app.use(express.json({ limit: '5mb' }))

// ========================================
// MYSQL DATABASE CONNECTION
// ========================================

if (!process.env.DB_USER) {
  throw new Error('DB_USER is missing. Check your main .env file.')
}

if (process.env.DB_PASSWORD === undefined) {
  throw new Error('DB_PASSWORD is missing. Check your main .env file.')
}

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'mediqueue_lesotho',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
})

// ========================================
// JWT CONFIGURATION
// ========================================

const JWT_SECRET = process.env.JWT_SECRET

if (!JWT_SECRET) {
  throw new Error('Set JWT_SECRET in your .env file.')
}

const sign = user => jwt.sign(
  {
    id: user.id,
    email: user.email,
    role: user.role,
    name: user.full_name
  },
  JWT_SECRET,
  { expiresIn: '8h' }
)

// ========================================
// AUTHENTICATION MIDDLEWARE
// ========================================

async function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '')
      .replace(/^Bearer\s+/i, '')

    if (!token) {
      return res.status(401).json({
        error: 'Please sign in.'
      })
    }

    const decoded = jwt.verify(token, JWT_SECRET)

    const [rows] = await pool.query(
      `SELECT
        u.user_id AS id,
        u.full_name,
        u.email,
        u.phone,
        r.role_name AS role,
        (u.account_status = 'active') AS is_active
       FROM users u
       JOIN roles r ON r.role_id = u.role_id
       WHERE u.user_id = ?
       LIMIT 1`,
      [decoded.id]
    )

    if (!rows.length || !rows[0].is_active) {
      return res.status(401).json({
        error: 'Account unavailable.'
      })
    }

    req.user = rows[0]
    next()

  } catch (error) {
    console.error('Authentication error:', error)

    return res.status(401).json({
      error: 'Session expired. Please sign in again.'
    })
  }
}

// ========================================
// ROLE PERMISSIONS
// ========================================

const allowRoles = (...roles) => (req, res, next) =>
  roles.includes(req.user.role)
    ? next()
    : res.status(403).json({
        error: 'You do not have permission.'
      })

// ========================================
// HEALTH CHECK
// ========================================

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1')

    res.json({
      ok: true,
      database: 'connected'
    })

  } catch (error) {
    console.error('Database health check failed:', error)

    res.status(503).json({
      ok: false,
      database: 'disconnected',
      message: error.message
    })
  }
})

// ========================================
// USERNAME GENERATOR
// ========================================

function makeUsername(email) {
  const base = (email.split('@')[0] || 'patient')
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, '')
    .slice(0, 45) || 'patient'

  return `${base}_${randomBytes(4).toString('hex')}`
}

// ========================================
// PATIENT NUMBER GENERATOR
// ========================================

function makePatientNumber() {
  return `MQP-${Date.now()}-${randomBytes(3).toString('hex').toUpperCase()}`
}

// ========================================
// PATIENT REGISTRATION
// ========================================

app.post('/api/auth/register', async (req, res) => {
  const { fullName, email, phone, password } = req.body || {}

  if (
    typeof fullName !== 'string' ||
    !fullName.trim() ||
    typeof email !== 'string' ||
    !email.trim() ||
    typeof password !== 'string' ||
    password.length < 8
  ) {
    return res.status(400).json({
      error: 'Enter your name, email and a password of at least 8 characters.'
    })
  }

  const normalizedEmail = email.trim().toLowerCase()

  let connection
  let transactionStarted = false

  try {
    connection = await pool.getConnection()

    const [existing] = await connection.query(
      'SELECT user_id FROM users WHERE email = ? LIMIT 1',
      [normalizedEmail]
    )

    if (existing.length) {
      return res.status(409).json({
        error: 'That email is already registered.'
      })
    }

    const [roleRows] = await connection.query(
      'SELECT role_id FROM roles WHERE role_name = ? LIMIT 1',
      ['patient']
    )

    if (!roleRows.length) {
      return res.status(500).json({
        error: 'The patient role is missing from the roles table.'
      })
    }

    const hash = await bcrypt.hash(password, 12)
    const username = makeUsername(normalizedEmail)
    const patientNumber = makePatientNumber()

    await connection.beginTransaction()
    transactionStarted = true

    const [userResult] = await connection.query(
      `INSERT INTO users
       (
         role_id,
         full_name,
         username,
         email,
         password_hash,
         phone,
         account_status
       )
       VALUES (?, ?, ?, ?, ?, ?, 'active')`,
      [
        roleRows[0].role_id,
        fullName.trim(),
        username,
        normalizedEmail,
        hash,
        typeof phone === 'string' ? phone.trim() || null : null
      ]
    )

    const userId = userResult.insertId

    await connection.query(
      `INSERT INTO patients
       (
         user_id,
         patient_number
       )
       VALUES (?, ?)`,
      [userId, patientNumber]
    )

    await connection.commit()
    transactionStarted = false

    const user = {
      id: userId,
      full_name: fullName.trim(),
      email: normalizedEmail,
      phone: typeof phone === 'string' ? phone.trim() || null : null,
      role: 'patient'
    }

    return res.status(201).json({
      message: 'Patient registered successfully.',
      token: sign(user),
      user
    })

  } catch (error) {
    if (connection && transactionStarted) {
      await connection.rollback()
    }

    console.error('Patient registration failed:', error)

    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        error: 'That email or username is already registered.'
      })
    }

    return res.status(500).json({
      error: 'Could not create account. Check the server terminal for the database error.'
    })

  } finally {
    if (connection) {
      connection.release()
    }
  }
})

// ========================================
// PATIENT AND STAFF LOGIN
// ========================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = typeof req.body?.email === 'string'
      ? req.body.email.trim().toLowerCase()
      : ''

    const password = typeof req.body?.password === 'string'
      ? req.body.password
      : ''

    const [rows] = await pool.query(
      `SELECT
        u.user_id AS id,
        u.full_name,
        u.email,
        u.phone,
        u.password_hash,
        r.role_name AS role,
        (u.account_status = 'active') AS is_active
       FROM users u
       JOIN roles r ON r.role_id = u.role_id
       WHERE u.email = ?
       LIMIT 1`,
      [email]
    )

    const user = rows[0]

    if (
      !user ||
      !user.is_active ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: 'Incorrect email or password.'
      })
    }

    const {
      password_hash,
      is_active,
      ...safeUser
    } = user

    return res.json({
      token: sign(safeUser),
      user: safeUser
    })

  } catch (error) {
    console.error('Login failed:', error)

    return res.status(500).json({
      error: 'Could not sign in.'
    })
  }
})

// ========================================
// VERIFY LOGGED-IN USER
// ========================================

app.get('/api/auth/me', auth, (req, res) => {
  res.json({
    user: req.user
  })
})

// ========================================
// CREATE STAFF ACCOUNT (ADMIN ONLY)
// ========================================

app.post(
  '/api/auth/create-staff',
  auth,
  allowRoles('admin'),
  async (req, res) => {
    const {
      fullName,
      email,
      phone,
      password,
      role
    } = req.body || {}

    if (
      !['clerk', 'pharmacist', 'admin'].includes(role) ||
      typeof fullName !== 'string' ||
      !fullName.trim() ||
      typeof email !== 'string' ||
      !email.trim() ||
      typeof password !== 'string' ||
      password.length < 8
    ) {
      return res.status(400).json({
        error: 'Provide name, email, password (8+ characters) and a valid staff role.'
      })
    }

    let connection

    try {
      connection = await pool.getConnection()

      const [roleRows] = await connection.query(
        'SELECT role_id FROM roles WHERE role_name = ? LIMIT 1',
        [role]
      )

      if (!roleRows.length) {
        return res.status(400).json({
          error: `The ${role} role is missing from the roles table.`
        })
      }

      const normalizedEmail = email.trim().toLowerCase()
      const hash = await bcrypt.hash(password, 12)

      await connection.query(
        `INSERT INTO users
         (
           role_id,
           full_name,
           username,
           email,
           password_hash,
           phone,
           account_status
         )
         VALUES (?, ?, ?, ?, ?, ?, 'active')`,
        [
          roleRows[0].role_id,
          fullName.trim(),
          makeUsername(normalizedEmail),
          normalizedEmail,
          hash,
          typeof phone === 'string' ? phone.trim() || null : null
        ]
      )

      return res.status(201).json({
        message: 'Staff account created successfully.',
        ok: true
      })

    } catch (error) {
      console.error('Staff account creation failed:', error)

      if (error.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({
          error: 'Email already exists.'
        })
      }

      return res.status(500).json({
        error: 'Could not create staff account.'
      })

    } finally {
      if (connection) {
        connection.release()
      }
    }
  }
)

// ========================================
// LOAD APPLICATION STATE
// ========================================

app.get('/api/state', auth, async (_req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT state_json, updated_at FROM app_state WHERE id = 1'
    )

    if (!rows.length) {
      return res.json({
        state: null
      })
    }

    const raw = rows[0].state_json

    res.json({
      state: typeof raw === 'string'
        ? JSON.parse(raw)
        : raw,
      updatedAt: rows[0].updated_at
    })

  } catch (error) {
    console.error('Loading application state failed:', error)

    res.status(500).json({
      error: 'Could not load MediQueue data',
      detail: error.message
    })
  }
})

// ========================================
// SAVE APPLICATION STATE
// ========================================

app.put(
  '/api/state',
  auth,
  allowRoles('admin', 'clerk', 'pharmacist', 'patient'),
  async (req, res) => {
    try {
      const state = JSON.stringify(req.body)

      await pool.query(
        `INSERT INTO app_state (id, state_json)
         VALUES (1, ?)
         ON DUPLICATE KEY UPDATE
         state_json = VALUES(state_json),
         updated_at = CURRENT_TIMESTAMP`,
        [state]
      )

      res.json({
        ok: true,
        saved: true
      })

    } catch (error) {
      console.error('Saving application state failed:', error)

      res.status(500).json({
        error: 'Could not save MediQueue data',
        detail: error.message
      })
    }
  }
)

// ========================================
// START SERVER
// ========================================

const port = Number(process.env.PORT || 5000)

app.listen(port, () => {
  console.log('====================================')
  console.log('     MEDIQUEUE LESOTHO API')
  console.log('====================================')
  console.log(`Server running: http://localhost:${port}`)
  console.log(`Frontend allowed: ${process.env.CLIENT_ORIGIN || 'configured CORS origins'}`)
  console.log(`Database user: ${process.env.DB_USER}`)
  console.log('Database: mediqueue_lesotho')
  console.log('====================================')
})
