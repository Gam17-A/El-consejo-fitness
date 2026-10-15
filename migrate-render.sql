-- Ejecutar esto en tu base PostgreSQL de Render (p.ej. psql $DATABASE_URL -f migrate-render.sql)
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(10) NOT NULL DEFAULT 'user';
UPDATE users SET role = 'admin' WHERE email = 'gersitopro123@gmail.com';  -- <-- CAMBIA por tu email
