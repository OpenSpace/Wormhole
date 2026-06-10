import 'dotenv/config';
import { z } from 'zod';

const envSchema = z.object({
  HTTP_PORT: z.coerce.number().default(25000),
  WORMHOLE_PORT: z.coerce.number().default(25001),
  SERVER_API_PATH: z.string(),
  CORS_ORIGIN: z.string(),
  DEBUG: z.coerce.boolean().default(false),
  ADMIN_AUTH_SDK_FILEPATH: z.string(),
  ADMIN_DB_SDK_FILEPATH: z.string(),
  DATABASE_FIREBASE_DATABASE_URL: z.httpUrl()
});

const result = envSchema.safeParse(process.env);

if (!result.success) {
  console.error('Invalid environment configuration:');
  console.error(result.error);
  process.exit(1);
}

export const env = result.data;
