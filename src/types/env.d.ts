declare namespace NodeJS {
  interface ProcessEnv {
    /** Path to the Firebase Admin Auth service account key JSON file */
    ADMIN_AUTH_SDK_FILEPATH: string;
    /** Path to the Firebase Admin Realtime Database service account key JSON file */
    ADMIN_DB_SDK_FILEPATH: string;
    /** Firebase Realtime Database URL */
    DATABASE_FIREBASE_DATABASE_URL: string;
    /** Port for the HTTP REST API server (default: 25000) */
    HTTP_PORT?: string;
    /** Port for the Wormhole TCP server (default: 25001) */
    WORMHOLE_PORT?: string;
    /** Base path prefix for all REST API routes */
    SERVER_API_PATH: string;
    /** Allowed CORS origin for the HTTP server */
    CORS_ORIGIN: string;
    /** Enable verbose debug logging (default: false) */
    DEBUG?: string;
  }
}
