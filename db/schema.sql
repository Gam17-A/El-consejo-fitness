-- El consejo fitness · Esquema PostgreSQL 13+ en Tercera Forma Normal (3FN)
-- Uso: psql "$DATABASE_URL" -f db/schema.sql
--
-- Por qué cumple 3FN (cada atributo depende de la clave, de toda la clave y de nada más):
--  * 1FN: sin listas ni grupos repetidos. "4x8 60kg" se separa en sets / reps / weight_kg;
--    los "me gusta" son filas de post_likes, no un arreglo.
--  * 2FN: las tablas con clave compuesta (workout_logs, weight_logs, post_likes) no tienen
--    atributos que dependan de solo una parte de la clave.
--  * 3FN: el nombre de un ejercicio vive solo en `exercises` (no se repite en cada rutina);
--    el autor se obtiene por JOIN con users (no se copia username en posts/comments);
--    workout_logs NO guarda user_id porque ya se deduce de routine_exercise -> routine -> user.

BEGIN;

CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username      VARCHAR(24)  NOT NULL CHECK (char_length(username) >= 3),
  email         VARCHAR(254) NOT NULL,
  password_hash TEXT         NOT NULL,            -- bcrypt generado en el servidor
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_uq    ON users (lower(email));
CREATE UNIQUE INDEX users_username_uq ON users (lower(username));

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,                    -- SHA-256 del token; el token solo vive en la cookie
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- Catálogo de ejercicios: el nombre se guarda una sola vez
CREATE TABLE exercises (
  id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(60) NOT NULL
);
CREATE UNIQUE INDEX exercises_name_uq ON exercises (lower(name));

CREATE TABLE routines (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        VARCHAR(40) NOT NULL,
  day_of_week SMALLINT NOT NULL DEFAULT 0 CHECK (day_of_week BETWEEN 0 AND 7), -- 0 = cualquier día, 1 = lunes ... 7 = domingo
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX routines_user_idx ON routines (user_id);

CREATE TABLE routine_exercises (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  routine_id  UUID NOT NULL REFERENCES routines(id)  ON DELETE CASCADE,
  exercise_id UUID NOT NULL REFERENCES exercises(id) ON DELETE RESTRICT,
  position    SMALLINT NOT NULL,
  sets        SMALLINT NOT NULL CHECK (sets BETWEEN 1 AND 99),
  reps        SMALLINT NOT NULL CHECK (reps BETWEEN 1 AND 999),
  weight_kg   NUMERIC(6,2) CHECK (weight_kg >= 0),   -- NULL = sin peso (peso corporal)
  UNIQUE (routine_id, position)
);

-- Ejercicio marcado como hecho en una fecha (el usuario se obtiene por JOIN)
CREATE TABLE workout_logs (
  routine_exercise_id UUID NOT NULL REFERENCES routine_exercises(id) ON DELETE CASCADE,
  log_date            DATE NOT NULL,
  PRIMARY KEY (routine_exercise_id, log_date)
);
CREATE INDEX workout_logs_date_idx ON workout_logs (log_date);

CREATE TABLE weight_logs (
  user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  log_date DATE NOT NULL,
  kg       NUMERIC(5,1) NOT NULL CHECK (kg BETWEEN 20 AND 400),
  PRIMARY KEY (user_id, log_date)
);

CREATE TABLE posts (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type       VARCHAR(10)   NOT NULL CHECK (type IN ('Tip','Pregunta')),
  title      VARCHAR(80)   NOT NULL,
  body       VARCHAR(1500) NOT NULL,
  created_at TIMESTAMPTZ   NOT NULL DEFAULT now()
);
CREATE INDEX posts_created_idx ON posts (created_at DESC);

CREATE TABLE comments (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  post_id    UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body       VARCHAR(500) NOT NULL,
  created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX comments_post_idx ON comments (post_id, created_at);

CREATE TABLE post_likes (
  post_id UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (post_id, user_id)
);

COMMIT;
