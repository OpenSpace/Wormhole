/*****************************************************************************************
 *                                                                                       *
 * Wormhole                                                                              *
 *                                                                                       *
 * Copyright (c) 2026-2026                                                               *
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

import { env } from './config/env';

// Color codes for console logs
const FgRed = '\x1b[31m';
const FgGreen = '\x1b[32m';
const FgWhite = '\x1b[37m';

/**
 * Logs a debug info message if `DEBUG` flag is set to true.
 *
 * @param message The message to log
 * @param params Any additional parameters to log
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function LDEBUG(message: string, ...params: any[]): void {
  if (env.DEBUG) {
    // eslint-disable-next-line no-console
    console.log(FgGreen, message, FgWhite, ...params);
  }
}
/**
 * Logs an error message.
 *
 * @param message The message to log
 * @param params Any additional parameters to log
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function LERROR(message: string, ...params: any[]): void {
  // eslint-disable-next-line no-console
  console.error(FgRed, message, FgWhite, ...params);
}

/**
 * Logs an info message.
 *
 * @param message The message to log
 * @param params Any additional parameters to log
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function LINFO(message: string, ...params: any[]): void {
  // eslint-disable-next-line no-console
  console.log(FgWhite, message, ...params);
}
