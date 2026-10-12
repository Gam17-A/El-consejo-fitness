# El consejo fitness

1. Crea una base PostgreSQL (local, Supabase, Neon, Railway...).
2. `psql "TU_CADENA_DE_CONEXION" -f db/schema.sql`
3. Copia `.env.example` a `.env` y pon tu `DATABASE_URL` (si tu proveedor exige SSL: `DB_SSL=true`).
4. `npm install` y luego `npm start`
5. Abre http://localhost:3000

En produccion: `NODE_ENV=production` y sirve la app detras de HTTPS (la cookie de sesion pasa a `secure`).
