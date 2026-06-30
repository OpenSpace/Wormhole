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

import { adminAuthApp, adminDbApp } from './adminFirebaseConfig';
import { Session } from './session';
import { SessionHistoryData, SessionData, StatisticData } from './types/types';
import { LDEBUG, LERROR, LINFO } from './utils';
import { getAuth, UserRecord } from 'firebase-admin/auth';
import { DataSnapshot, EventType, getDatabase, Reference } from 'firebase-admin/database';

/**
 * Set admin rights for a user in the firebase auth database.
 *
 * @param uid The user uid to set admin rights for
 * @param secret The secret to verify the request
 */
export async function setAdminRights(uid: string, secret: string) {
  // Verify the provided secret against the database secret
  const db = getDatabase(adminDbApp);
  const dbSecret = await db.ref('Admin/secret').get();

  if (!dbSecret.exists()) {
    throw new Error('Could not find admin secret in database');
  }

  if (secret !== dbSecret.val()) {
    throw new Error('Invalid secret provided');
  }

  const auth = getAuth(adminAuthApp);
  try {
    await auth.setCustomUserClaims(uid, { admin: true });
    LINFO(`Successfully set admin rights for user: ${uid}`);
  } catch (error) {
    LERROR('Internal error', (error as Error).message, `uid: '${uid}'`);
    throw error;
  }
}

/**
 * Authorize a user to the firebase auth database.
 *
 * @param token The client user id token to authorize
 * @return A promise that resolves with the user firebase uid
 */
export async function authorizeUser(token: string): Promise<string> {
  const auth = getAuth(adminAuthApp);
  const decodedToken = await auth.verifyIdToken(token);
  return decodedToken.uid;
}

/**
 * Fetch the display name of a user given their uid.
 *
 * @param token Token to fetch user information
 * @return A promise that resolves with the user information
 */
export async function getUserByID(token: string): Promise<UserRecord> {
  const auth = getAuth(adminAuthApp);
  return await auth.getUser(token);
}

/**
 * @return A promise that resolves with an array of server instances or empty array
 */
export async function getSessionsFromDb(): Promise<SessionData[]> {
  const db = getDatabase(adminDbApp);
  const snapshot = await db.ref('SessionData').once('value');
  if (!snapshot.exists()) {
    return [];
  }

  const data = snapshot.val();
  const instances = Object.values<SessionData>(data);
  return instances;
}

/**
 * Subscribe to the database at `path` and listen for `eventType` events.
 *
 * @param path The path to the database to subscribe to
 * @param eventType The type of event to listen for
 * @param callback The callback function when an event is triggered
 * @param onError The callback function when an error occurs
 */
export async function subscribeToDatabase(
  path: string | Reference,
  eventType: EventType,
  callback: (snapshot: DataSnapshot, b?: string | null | undefined) => any,
  onError: (error: Error) => any
) {
  const db = getDatabase(adminDbApp);
  const instanceRef = db.ref(path);
  instanceRef.on(eventType, callback, onError);
}

/**
 * Adds a new server instance to the database.
 *
 * @param session The server instance to add to the database
 * @param profile The OpenSpace profile this instance is running
 * @param isPrivate True if instance is private, false otherwise
 * @param uid The uid of the user who created this instance
 */
export async function postSession(
  session: Session,
  profile: string,
  isPrivate: boolean,
  uid: string
): Promise<SessionData> {
  const db = getDatabase(adminDbApp);
  const sessionsRef = db.ref('SessionData');
  const newPostRef = sessionsRef.push();
  const postId = newPostRef.key!;

  const metadata = session.getSessionMetadata();

  await db.ref(`SessionSecrets/${postId}`).set({ hostPassword: metadata.hostPassword });
  LDEBUG(`Posted host password to database for session: ${postId}`);

  const data: SessionData = {
    active: false,
    inactiveTimeStamp: Date.now(),
    created: Date.now(),
    usage: 0,
    password: metadata.password ?? null,
    nPeers: 0,
    currentHost: 'null',
    roomName: metadata.sessionName,
    profile: profile,
    id: postId,
    isPrivate: isPrivate,
    owner: uid
  };
  await newPostRef.set(data);
  LDEBUG('Posted a new instance to database:', data);
  return data;
}

/***
 * Fetch the host password for a given session ID and user ID.
 *
 * @param sessionId The ID of the session to fetch the host password for
 * @param uid The user ID of the requester
 */
export async function getHostPassword(sessionId: string, uid: string): Promise<string> {
  const db = getDatabase(adminDbApp);

  const sessionSnapshot = await db.ref(`SessionData/${sessionId}`).get();
  if (!sessionSnapshot.exists()) {
    throw new Error(`Session with id "${sessionId}" does not exist`);
  }

  const session = sessionSnapshot.val() as SessionData;
  if (session.owner !== uid) {
    throw new Error('Only the session owner can retrieve the host password');
  }

  const secretSnapshot = await db.ref(`SessionSecrets/${sessionId}/hostPassword`).get();
  if (!secretSnapshot.exists()) {
    throw new Error(`Host password for session with id "${sessionId}" does not exist`);
  }

  return secretSnapshot.val();
}

export async function verifyHostPassword(
  sessionId: string,
  password: string
): Promise<boolean> {
  const db = getDatabase(adminDbApp);
  const snapshot = await db.ref(`SessionSecrets/${sessionId}/hostPassword`).get();
  if (!snapshot.exists()) {
    throw new Error(`Host password for session with id "${sessionId}" does not exist`);
  }
  return snapshot.val() === password;
}

/**
 * Fetch the host password for a session for server-internal use only.
 * Does not perform any ownership or authentication check.
 *
 * @param sessionId The ID of the session
 * @return The host password, or null if not found
 */
export async function getHostPasswordInternal(sessionId: string): Promise<string | null> {
  const db = getDatabase(adminDbApp);
  const snapshot = await db.ref(`SessionSecrets/${sessionId}/hostPassword`).get();
  return snapshot.exists() ? snapshot.val() : null;
}

/**
 * Add the `instance` to the history database.
 *
 * @param session The instance data to add to the history database
 */
export async function postSessionHistoryData(session: SessionData): Promise<void> {
  try {
    const db = getDatabase(adminDbApp);
    const uptime = Date.now() - session.created;
    const historyRef = db.ref(`SessionHistory/${session.id}`);
    const history: SessionHistoryData = {
      id: session.id,
      inactiveTimeStamp: session.inactiveTimeStamp,
      created: session.created,
      uptime: uptime,
      usage: session.usage,
      roomName: session.roomName,
      owner: session.owner
    };
    await historyRef.set(history);
    LDEBUG('Posted history data to database:', history);
  } catch (error) {
    LERROR('Error posting history data:', error);
  }
}

/**
 * Attempts to remove the server instance with the given ID from the database.
 *
 * @param sessionId The ID of the server instance to remove
 * @return A promise once the operation is complete or an exception if an error occurs
 */
export async function removeSessionFromDb(sessionId: string): Promise<void> {
  try {
    const db = getDatabase(adminDbApp);
    const instanceRef = db.ref(`SessionData/${sessionId}`);

    const snapshot = await instanceRef.get();

    if (!snapshot.exists()) {
      const errorMessage = `Error removing instance from database: "${sessionId}" does not exist`;
      LDEBUG(errorMessage);
      throw new Error(errorMessage);
    }

    await postSessionHistoryData(snapshot.val());
    await instanceRef.remove();
    await db.ref(`SessionSecrets/${sessionId}`).remove();
    LINFO(`Instance with id ${sessionId} was removed from the database`);
  } catch (error) {
    const errorMessage = `Error removing instance "${sessionId}" from DB: ${(error as Error).message}`;
    LERROR(errorMessage);
    throw new Error(errorMessage);
  }
}

/**
 * Updates the active status of a server instance in the database.
 *
 * @param sessionId The ID of the server instance to update
 * @param online The new status of the server instance
 */
export async function updateActiveSessionStatus(
  sessionId: string,
  online: boolean
): Promise<void> {
  try {
    const db = getDatabase(adminDbApp);
    const instanceRef = db.ref(`SessionData/${sessionId}`);
    const snapshot = await instanceRef.get();

    if (!snapshot.exists()) {
      throw new Error(`Could not find instance with id "${sessionId}"`);
    }
    // if instance is offline we also need to update the inactive timestamp
    if (!online) {
      await instanceRef.update({ active: online, inactiveTimeStamp: Date.now() });
    } else {
      await instanceRef.update({ active: online });
    }
    LDEBUG(`Updated session status for "${sessionId}" to: ${online}`);
  } catch (error) {
    LERROR(`Error updating session status for "${sessionId}:"`, error);
  }
}

/**
 * Updates the current number of active users in a server instance.
 *
 * @param sessionId The ID of the server instance to update
 * @param nPeers The new number of active users
 */
export async function updateCurrentActiveUsers(
  sessionId: string,
  nPeers: number
): Promise<void> {
  try {
    const db = getDatabase(adminDbApp);
    const instanceRef = db.ref(`SessionData/${sessionId}`);
    const snapshot = await instanceRef.get();

    if (!snapshot) {
      throw new Error(`Could not find instance with id "${sessionId}"`);
    }

    await instanceRef.update({ nPeers: nPeers });
    LDEBUG(`Updated # active users for "${sessionId}" to: ${nPeers}`);
  } catch (error) {
    LERROR(`Error updating # active users for "${sessionId}:"`, error);
  }
  await updateStatistics(sessionId, nPeers);
}

/**
 * Add a new statistics entry for the given `instanceID` instance.
 *
 * @param sessionId The ID of the server instance to update
 * @param nPeers The new number of active users
 */
export async function updateStatistics(sessionId: string, nPeers: number): Promise<void> {
  try {
    const db = getDatabase(adminDbApp);
    const statisticsRef = db.ref(`Statistics/${sessionId}`);
    const stats: StatisticData = {
      nPeers: nPeers,
      timestamp: Date.now()
    };

    await statisticsRef.push(stats);
    LDEBUG('Pushed new statistics to database:', stats);
  } catch (error) {
    LERROR(`Error updating statistics for "${sessionId}:"`, error);
  }
}
/**
 * Updates the current host of a server instance.
 *
 * @param sessionId The ID of the server instance to update
 * @param host The new host of the server instance
 */
export async function updateCurrentHost(sessionId: string, host: string) {
  try {
    const db = getDatabase(adminDbApp);
    const instanceRef = db.ref(`SessionData/${sessionId}`);
    const snapshot = await instanceRef.get();
    if (!snapshot.exists()) {
      throw new Error(`Could not find instance with id "${sessionId}"`);
    }
    await instanceRef.update({ currentHost: host });
    LDEBUG(`Updated current host for "${sessionId}" to: ${host}`);
  } catch (error) {
    LERROR(`Error updating current host for ${sessionId}:`, error);
  }
}

/**
 * Updates the total number of users connected to a server instance.
 *
 * @param sessionId The ID of the server instance to update
 */
export async function updateUsage(sessionId: string) {
  try {
    const db = getDatabase(adminDbApp);
    const instanceRef = db.ref(`SessionData/${sessionId}`);
    const snapshot = await instanceRef.get();
    if (!snapshot.exists()) {
      throw new Error(`Could not find instance with id "${sessionId}"`);
    }
    const data = snapshot.val() as SessionData;
    await instanceRef.update({ usage: data.usage + 1 });
    LDEBUG(`Updated usage for "${sessionId}" to: ${data.usage + 1}`);
  } catch (error) {
    LERROR(`Error updating instance ${sessionId} usage:`, error);
  }
}
