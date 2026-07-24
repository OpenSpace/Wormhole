/*****************************************************************************************
 *                                                                                       *
 * Wormhole                                                                              *
 *                                                                                       *
 * Copyright (c) 2026                                                                    *
 *                                                                                       *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this  *
 * software and associated documentation files (the "Software"), to deal in the Software *
 * without restriction, including without limitation the rights to use, copy, modify,    *
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to    *
 * permit persons to whom the Software is furnished to do so, subject to the following   *
 * conditions:                                                                           *
 *                                                                                       *
 * The above copyright notice and this permission notice shall be included in all copies *
 * or substantial portions of the Software.                                              *
 *                                                                                       *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,   *
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A         *
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT    *
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF  *
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE  *
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                                         *
 ****************************************************************************************/

import { cert, initializeApp } from 'firebase-admin/app';
import { readFileSync } from 'fs';

import { env } from './config/env';

function loadServiceAccount(filePath: string, envVar: string): object {
  try {
    return JSON.parse(readFileSync(filePath, 'utf-8'));
  } catch (error) {
    throw new Error(
      `Failed to load Firebase service account from ${envVar}="${filePath}": ` +
        `${(error as Error).message}`,
      { cause: error }
    );
  }
}

// Setup admin auth app
export const adminAuthApp = initializeApp(
  {
    credential: cert(
      loadServiceAccount(env.ADMIN_AUTH_SDK_FILEPATH, 'ADMIN_AUTH_SDK_FILEPATH')
    )
  },
  'adminAuth'
);

// Setup admin database app
export const adminDbApp = initializeApp(
  {
    credential: cert(
      loadServiceAccount(env.ADMIN_DB_SDK_FILEPATH, 'ADMIN_DB_SDK_FILEPATH')
    ),
    databaseURL: env.DATABASE_FIREBASE_DATABASE_URL
  },
  'adminDb'
);
