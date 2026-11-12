
import 'dotenv/config'
import mysql from 'mysql2/promise'
import bcrypt from 'bcryptjs'
import { randomBytes } from 'node:crypto'

const {
  ADMIN_NAME,
  ADMIN_EMAIL,
  ADMIN_PASSWORD
} = process.env

if (
  !ADMIN_NAME ||
  !ADMIN_EMAIL ||
  !ADMIN_PASSWORD ||
  ADMIN_PASSWORD.length < 8
) {
  console.error(
    'Set ADMIN_NAME, ADMIN_EMAIL and ADMIN_PASSWORD (8+ characters) in .env first.'
  )
  process.exit(1)
}

const db = await mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'mediqueue_lesotho'
})

try {
  // Find admin role
  const [roles] = await db.execute(
    'SELECT role_id FROM roles WHERE role_name = ? LIMIT 1',
    ['admin']
  )

  if (!roles.length) {
    throw new Error(
      'The admin role is missing from the roles table.'
    )
  }

  const email = ADMIN_EMAIL.trim().toLowerCase()

  const hash = await bcrypt.hash(ADMIN_PASSWORD, 12)

  const usernameBase = (email.split('@')[0] || 'admin')
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, '')
    .slice(0, 45) || 'admin'

  const username =
    `${usernameBase}_${randomBytes(4).toString('hex')}`

  // Check whether admin already exists
  const [existing] = await db.execute(
    'SELECT user_id FROM users WHERE email = ? LIMIT 1',
    [email]
  )

  if (existing.length) {

    // Update existing account
    await db.execute(
      `UPDATE users
       SET
         full_name = ?,
         password_hash = ?,
         role_id = ?,
         account_status = 'active'
       WHERE user_id = ?`,
      [
        ADMIN_NAME,
        hash,
        roles[0].role_id,
        existing[0].user_id
      ]
    )

  } else {

    // Create new administrator
    await db.execute(
      `INSERT INTO users
       (
         role_id,
         full_name,
         username,
         email,
         password_hash,
         account_status
       )
       VALUES (?, ?, ?, ?, ?, 'active')`,
      [
        roles[0].role_id,
        ADMIN_NAME,
        username,
        email,
        hash
      ]
    )
  }

  console.log(
    `Administrator account ready: ${email}`
  )

} catch (error) {

  console.error(
    'Admin creation failed:',
    error.message
  )

  process.exitCode = 1

} finally {
  await db.end()
}
