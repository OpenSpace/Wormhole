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

import cors from 'cors';
import express, { Request, Response } from 'express';
import { DataSnapshot } from 'firebase-admin/database';

import { env } from './config/env';
import { SessionData } from './types/types';
import {
  authorizeAdmin,
  authorizeUser,
  getHostPassword,
  getHostPasswordInternal,
  getSessionsFromDb,
  getUserByID,
  postSession,
  removeSessionFromDb,
  setAdminRights,
  subscribeToDatabase,
  verifyHostPassword
} from './adminApi';
import { LERROR, LINFO } from './utils';
import { Wormhole } from './wormhole';

/**
 * Top-level application coordinator. Owns the HTTP REST API and the Wormhole TCP server.
 * Responsible for session lifecycle management, Firebase persistence, and authentication.
 */
export class App {
  /**
   * The Wormhole instance managing all active sessions
   */
  private _wormhole: Wormhole;

  /**
   * The express server that is listening to incoming HTTP requests
   */
  private _app;

  /**
   * @param httpPort The port on which the HTTP server will listen for incoming requests
   * @param wormholePort The port on which the Wormhole will listen for incoming peer
   * connections
   * @param apiPath The path to the API endpoint for the server, e.g. `/api`
   */
  constructor(httpPort: number, wormholePort: number, apiPath: string) {
    this._wormhole = new Wormhole(wormholePort);

    // Setup express server for handling HTTP requests
    this._app = express();
    this._app.use(cors({ origin: env.CORS_ORIGIN }));
    this._app.use(express.json());

    this._app.post(
      `${apiPath}/request-admin-rights`,
      this.handleRequestSetAdminRights.bind(this)
    );
    this._app.get(
      `${apiPath}/fetch-user-name/:uid`,
      this.handleRequestGetUserNameByID.bind(this)
    );
    this._app.post(`${apiPath}/request-session`, this.handleRequestSession.bind(this));
    this._app.get(
      `${apiPath}/session/:id/host-password`,
      this.handleGetHostPassword.bind(this)
    );
    this._app.post(`${apiPath}/session/:id/claim-host`, this.handleClaimHost.bind(this));
    this._app.delete(
      `${apiPath}/session/:id/remove`,
      this.handleRemoveSession.bind(this)
    );

    this._app.listen(httpPort, () => {
      LINFO(`HTTP server: listening on port ${httpPort}`);
    });
  }

  /**
   * Starts the Wormhole to accept incoming peer connections.
   */
  public startWormhole(): void {
    this._wormhole.start();
  }

  /**
   * Fetch the display name of a user given their uid.
   *
   * @param req Request params must contain the user uid as `/:uid`
   * @param res Response object containing user name
   */
  private async handleRequestGetUserNameByID(req: Request, res: Response): Promise<void> {
    const { uid } = req.params;

    if (!uid || typeof uid !== 'string') {
      res.status(400).json({ error: 'Invalid uid' });
      return;
    }

    try {
      const user = await getUserByID(uid);
      res.json({ name: user.displayName });
    } catch (error) {
      res.status(400).json({ error: (error as Error).message });
    }
  }

  /**
   * Loads existing sessions from the database and restores them in the Wormhole.
   */
  public async loadSessionsFromDB(): Promise<void> {
    const instances = await getSessionsFromDb();

    if (!instances || !instances.length) {
      LINFO('Database: no existing sessions found in database');
      return;
    }
    // Add sessions to internal registry
    for (const instance of instances) {
      const hostPassword = (await getHostPasswordInternal(instance.id)) ?? '';
      await this._wormhole.addSession(
        instance.roomName,
        instance.password,
        hostPassword,
        instance.id
      );
    }

    LINFO(
      `Database: loaded ${this._wormhole.activeSessions()} existing session(s) from ` +
        `the database`
    );
  }

  /**
   * Handle the request to set admin rights for a user.
   *
   * @param req Request object must contain the user id token and secret in the body
   */
  private async handleRequestSetAdminRights(req: Request, res: Response): Promise<void> {
    const { uid } = req.body;
    const { secret } = req.body;

    if (!uid || !secret || typeof uid !== 'string' || typeof secret !== 'string') {
      res.status(400).json({ error: 'Missing uid or secret' });
      return;
    }

    try {
      await setAdminRights(uid, secret);
      res.status(200).json({ message: `Successfully set admin rights for user: ${uid}` });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  /**
   * Handle the request to remove a session. Only users with admin rights may remove a
   * session.
   *
   * @param req Request params must contain the session id as `/:id`; must include a
   * valid admin Bearer token in the authorization header
   */
  private async handleRemoveSession(req: Request, res: Response): Promise<void> {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Missing or invalid authorization header' });
      return;
    }
    const token = authHeader.slice(7);
    const instanceID = req.params.id;

    if (!instanceID || typeof instanceID !== 'string') {
      res.status(400).json({ error: 'Instance ID is required' });
      return;
    }

    try {
      await authorizeAdmin(token);
      const msg = await this.removeSession(instanceID);
      res.status(200).json({ message: msg });
    } catch (e) {
      const msg = (e as Error).message;
      if (msg.includes('Insufficient permissions')) {
        res.status(403).json({ error: msg });
      } else {
        res.status(500).json({ error: msg });
      }
    }
  }

  /**
   * Shuts down and removes a session from the Wormhole and the database.
   *
   * @param instanceID The id of the session to shut down
   * @return A promise that resolves with a success message, or rejects with an error
   */
  private async removeSession(instanceID: string): Promise<string> {
    const msg = await this._wormhole.removeSession(instanceID);
    await removeSessionFromDb(instanceID);
    return msg;
  }

  /**
   * Handle the request to create a new session.
   *
   * @param req Request body must contain password, hostpassword, roomname, profile, and
   * token
   * @param res Response object that will receive the session metadata on success
   */
  private async handleRequestSession(req: Request, res: Response): Promise<void> {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Missing or invalid authorization header' });
      return;
    }
    const token = authHeader.slice(7);

    const { password } = req.body;
    const { hostPassword } = req.body;
    const { roomName } = req.body;
    const { profile } = req.body;
    const isPrivateRoom = req.body.isPrivate ?? false;
    // A server without passwords are not allowed
    if (!hostPassword || typeof hostPassword !== 'string') {
      res.status(400).json({ error: 'Missing host password' });
      return;
    }
    if (password !== undefined && typeof password !== 'string') {
      res.status(400).json({ error: 'Invalid password' });
      return;
    }
    if (!roomName || typeof roomName !== 'string') {
      res.status(400).json({ error: 'Missing room name' });
      return;
    }
    if (!profile || typeof profile !== 'string') {
      res.status(400).json({ error: 'Missing profile' });
      return;
    }

    // Check if the provided room name is unique
    const sessions = await getSessionsFromDb();
    const isRoomNameUnique = sessions.every((instance: SessionData) => {
      return instance.roomName !== roomName;
    });

    if (!isRoomNameUnique) {
      res
        .status(400)
        .json({ error: 'A room with that name already exists, must be unique' });
      return;
    }

    // Attempt to create a new server instance
    try {
      // Authorize potential user
      const uid = await authorizeUser(token);
      const session = await this._wormhole.addSession(roomName, password, hostPassword);

      let sessionData: SessionData;
      try {
        sessionData = await postSession(session, profile, isPrivateRoom, uid);
      } catch (error) {
        await this._wormhole.removeSession(session);
        LERROR(
          `Session '${roomName}': failed to post session to database, rolling back ` +
            `Wormhole session`,
          error
        );
        res.status(500).json({ error: 'Failed to create session, please try again' });
        return;
      }
      session.setSessionID(sessionData.id);
      // Server was successfully created, send back information to the client so they
      // can connect to it through OpenSpace
      res.json(sessionData);
    } catch (error) {
      LERROR(`Session '${roomName}': failed to create server instance`, error);
      // Report an internal server error to the client
      res.status(500).json({ error: (error as Error).message });
      return;
    }
  }

  /**
   * Handle the request to retrieve the host password for a session. Only the session
   * owner may access it.
   *
   * @param req Request params must contain the session id as `/:id`
   */
  private async handleGetHostPassword(req: Request, res: Response): Promise<void> {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Missing or invalid authorization header' });
      return;
    }
    const token = authHeader.slice(7);
    const sessionId = req.params.id;

    if (!sessionId || typeof sessionId !== 'string') {
      res.status(400).json({ error: 'Session ID is required' });
      return;
    }

    try {
      const uid = await authorizeUser(token);
      const hostPassword = await getHostPassword(sessionId, uid);
      res.status(200).json({ hostPassword });
    } catch (error) {
      const msg = (error as Error).message;
      if (msg.includes('Only the session owner')) {
        res.status(403).json({ error: msg });
      } else if (msg.includes('does not exist')) {
        res.status(404).json({ error: msg });
      } else {
        res.status(500).json({ error: msg });
      }
    }
  }

  /**
   * Handle a request to claim host for a session. Verifies the provided host password,
   * does not check whether a host is currently active
   *
   * @param req Request params must contain the session id as `/:id`; body must contain
   * `password`
   */
  private async handleClaimHost(req: Request, res: Response): Promise<void> {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Missing or invalid authorization header' });
      return;
    }
    const token = authHeader.slice(7);
    const sessionId = req.params.id;
    const { password } = req.body;

    if (!sessionId || typeof sessionId !== 'string') {
      res.status(400).json({ error: 'Session ID is required' });
      return;
    }

    if (!password || typeof password !== 'string') {
      res.status(400).json({ error: 'Missing password' });
      return;
    }

    try {
      await authorizeUser(token);
      const isValid = await verifyHostPassword(sessionId, password);
      if (isValid) {
        res.status(200).json({ message: 'Host password verified' });
      } else {
        res.status(403).json({ error: 'Invalid host password' });
      }
    } catch (error) {
      const msg = (error as Error).message;
      if (msg.includes('does not exist')) {
        res.status(404).json({ error: msg });
      } else {
        res.status(500).json({ error: msg });
      }
    }
  }

  /**
   * Automatically removes sessions that have been inactive for more than 30 minutes.
   * Runs every 5 minutes.
   */
  public autoKillInactiveSessions(): void {
    let sessions: SessionData[] = [];

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    function handleData(snapshot: DataSnapshot): any {
      if (snapshot.exists()) {
        const data = snapshot.val();
        sessions = Object.values<SessionData>(data);
      } else {
        sessions = [];
      }
    }

    function handleError(error: Error) {
      LERROR(`Database: failed to fetch session data`, error);
    }

    subscribeToDatabase('SessionData', 'value', handleData, handleError);

    setInterval(
      async () => {
        const now = Date.now();
        const thirtyMinutes = 30 * 60 * 1000;
        // We use an extra array to store the instance we want to remove.
        // Because the removeServerInstanceFromDb will alter the firebase and we are
        // subscribed to the database, as such the `instances` array will update while
        // we would be looping over it, unsure of the behaviour of that.
        const sessionsToRemove: SessionData[] = [];
        for (const session of sessions) {
          // If the server has been running for more than 30 inactive minutes we kill it
          const inactiveUptime = now - session.inactiveTimeStamp;
          if (!session.active && inactiveUptime > thirtyMinutes) {
            sessionsToRemove.push(session);
          }
        }

        // Remove the sessions that have been inactive for too long
        for (const session of sessionsToRemove) {
          try {
            await this._wormhole.removeSession(session.id);
            await removeSessionFromDb(session.id);
          } catch (error) {
            LERROR(`Session '${session.id}': failed to remove inactive session`, error);
          }
        }
      },
      5 * 60 * 1000 // Run every 5 minutes
    );
  }
}
