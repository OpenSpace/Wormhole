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
import { InstanceHistoryData, ServerInstanceData, StatisticData } from './types/types';
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
export async function getServerInstancesFromDB(): Promise<ServerInstanceData[]> {
  const db = getDatabase(adminDbApp);
  const snapshot = await db.ref('InstanceData').once('value');
  if (!snapshot.exists()) {
    return [];
  }

  const data = snapshot.val();
  const instances = Object.values<ServerInstanceData>(data);
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
 * @param server The server instance to add to the database
 * @param profile The OpenSpace profile this instance is running
 * @param isPrivate True if instance is private, false otherwise
 * @param uid The uid of the user who created this instance
 */
export async function postServerInstance(
  server: Session,
  profile: string,
  isPrivate: boolean,
  uid: string | null
): Promise<ServerInstanceData> {
  const db = getDatabase(adminDbApp);
  const instanceRef = db.ref('InstanceData');
  const newPostRef = instanceRef.push();
  const postID = newPostRef.key!;

  const metadata = server.getSessionMetadata();
  const data: ServerInstanceData = {
    active: false,
    inactiveTimeStamp: Date.now(),
    created: Date.now(),
    usage: 0,
    password: metadata.password,
    hostPassword: metadata.hostPassword,
    nPeers: 0,
    currentHost: 'null',
    roomName: metadata.sessionName,
    profile: profile,
    id: postID,
    isPrivate: isPrivate,
    owner: uid
  };
  await newPostRef.set(data, (error) => {
    if (error) {
      LERROR('Error posting instance to database:', error);
    } else {
      LDEBUG('Posted a new instance to database:', data);
    }
  });
  return data;
}

/**
 * Add the `instance` to the history database.
 *
 * @param instance The instance data to add to the history database
 */
export async function postInstanceHistoryData(
  instance: ServerInstanceData
): Promise<void> {
  try {
    const db = getDatabase(adminDbApp);
    const uptime = Date.now() - instance.created;
    const historyRef = db.ref(`InstanceHistory/${instance.id}`);
    const history: InstanceHistoryData = {
      id: instance.id,
      inactiveTimeStamp: instance.inactiveTimeStamp,
      created: instance.created,
      uptime: uptime,
      usage: instance.usage,
      roomName: instance.roomName,
      owner: instance.owner
    };
    await historyRef.set(history, (error) => {
      if (error) {
        throw error;
      } else {
        LDEBUG('Posted history data to database:', history);
      }
    });
  } catch (error) {
    LERROR('Error posting history data:', error);
  }
}

/**
 * Attempts to remove the server instance with the given ID from the database.
 *
 * @param instanceID The ID of the server instance to remove
 * @return A promise once the operation is complete or an exception if an error occurs
 */
export async function removeServerInstanceFromDb(instanceID: string): Promise<void> {
  try {
    const db = getDatabase(adminDbApp);
    const instanceRef = db.ref(`InstanceData/${instanceID}`);

    const snapshot = await instanceRef.get();

    if (!snapshot.exists()) {
      const errorMessage = `Error removing instance from database: "${instanceID}" does not exist`;
      LDEBUG(errorMessage);
      throw new Error(errorMessage);
    }

    await postInstanceHistoryData(snapshot.val());
    await instanceRef.remove((error) => {
      if (error) {
        LERROR('Error removing server instance from database:', error);
      } else {
        LINFO(`Instance with id ${instanceID} was removed from the database`);
      }
    });
  } catch (error) {
    const errorMessage = `Error removing instance "${instanceID}" from DB: ${(error as Error).message}`;
    LERROR(errorMessage);
    throw new Error(errorMessage);
  }
}

/**
 * Updates the active status of a server instance in the database.
 *
 * @param instanceID The ID of the server instance to update
 * @param online The new status of the server instance
 */
export async function updateActiveSessionStatus(
  instanceID: string,
  online: boolean
): Promise<void> {
  const onUpdate = (error: Error | null) => {
    if (error) {
      throw error;
    } else {
      LDEBUG(`Updated session status for "${instanceID}" to: ${online}`);
    }
  };

  try {
    const db = getDatabase(adminDbApp);
    const instanceRef = db.ref(`InstanceData/${instanceID}`);
    const snapshot = await instanceRef.get();

    if (!snapshot.exists()) {
      throw new Error(`Could not find instance with id "${instanceID}"`);
    }
    // if instance is offline we also need to update the inactive timestamp
    if (!online) {
      await instanceRef.update(
        { active: online, inactiveTimeStamp: Date.now() },
        onUpdate
      );
    } else {
      await instanceRef.update({ active: online }, onUpdate);
    }
  } catch (error) {
    LERROR(`Error updating session status for "${instanceID}:"`, error);
  }
}

/**
 * Updates the current number of active users in a server instance.
 *
 * @param instanceID The ID of the server instance to update
 * @param nPeers The new number of active users
 */
export async function updateCurrentActiveUsers(
  instanceID: string,
  nPeers: number
): Promise<void> {
  try {
    const db = getDatabase(adminDbApp);
    const instanceRef = db.ref(`InstanceData/${instanceID}`);
    const snapshot = await instanceRef.get();

    if (!snapshot) {
      throw new Error(`Could not find instance with id "${instanceID}"`);
    }

    await instanceRef.update({ nPeers: nPeers }, (error) => {
      if (error) {
        throw error;
      } else {
        LDEBUG(`Updated # active users for "${instanceID}" to: ${nPeers}`);
      }
    });
  } catch (error) {
    LERROR(`Error updating # active users for "${instanceID}:"`, error);
  }
  await updateStatistics(instanceID, nPeers);
}

/**
 * Add a new statistics entry for the given `instanceID` instance.
 *
 * @param instanceID The ID of the server instance to update
 * @param nPeers The new number of active users
 */
export async function updateStatistics(
  instanceID: string,
  nPeers: number
): Promise<void> {
  try {
    const db = getDatabase(adminDbApp);
    const statisticsRef = db.ref(`Statistics/${instanceID}`);
    const stats: StatisticData = {
      nPeers: nPeers,
      timestamp: Date.now()
    };

    await statisticsRef.push(stats, (error) => {
      if (error) {
        throw error;
      } else {
        LDEBUG('Pushed new statistics to database:', stats);
      }
    });
  } catch (error) {
    LERROR(`Error updating statistics for "${instanceID}:"`, error);
  }
}
/**
 * Updates the current host of a server instance.
 *
 * @param instanceID The ID of the server instance to update
 * @param host The new host of the server instance
 */
export async function updateCurrentHost(instanceID: string, host: string) {
  try {
    const db = getDatabase(adminDbApp);
    const instanceRef = db.ref(`InstanceData/${instanceID}`);
    const snapshot = await instanceRef.get();
    if (!snapshot.exists()) {
      throw new Error(`Could not find instance with id "${instanceID}"`);
    }
    await instanceRef.update({ currentHost: host }, (error) => {
      if (error) {
        throw error;
      } else {
        LDEBUG(`Updated current host for "${instanceID}" to: ${host}`);
      }
    });
  } catch (error) {
    LERROR(`Error updating current host for ${instanceID}:`, error);
  }
}

/**
 * Updates the total number of users connected to a server instance.
 *
 * @param instanceID The ID of the server instance to update
 */
export async function updateUsage(instanceID: string) {
  try {
    const db = getDatabase(adminDbApp);
    const instanceRef = db.ref(`InstanceData/${instanceID}`);
    const snapshot = await instanceRef.get();
    if (!snapshot.exists()) {
      throw new Error(`Could not find instance with id "${instanceID}"`);
    }
    const data = snapshot.val() as ServerInstanceData;
    await instanceRef.update({ usage: data.usage + 1 }, (error) => {
      if (error) {
        throw error;
      } else {
        LDEBUG(`Updated usage for "${instanceID}" to: ${data.usage + 1}`);
      }
    });
  } catch (error) {
    LERROR(`Error updating instance ${instanceID} usage:`, error);
  }
}
