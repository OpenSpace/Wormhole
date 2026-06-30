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

import { Session } from './session';
import {
  ConnectionStatus,
  CurrentProtocolVersion,
  MessageType,
  Peer
} from './types/types';
import { LDEBUG, LERROR, LINFO, toString } from './utils';
import * as net from 'net';

/**
 * A TCP server that listens on a single port and routes incoming OpenSpace connections
 * into their respective named sessions. Manages the full lifecycle of all active sessions.
 */
export class Wormhole {
  /**
   * The port on which this TCP server is listening
   */
  private _port: number;

  private _peerIdCounter: number;

  /**
   * All sessions currently managed by this Wormhole, keyed by session name.
   */
  private _sessions: { [name: string]: Session } = {};

  /**
   * The local server that is listening to incoming connections that will result in Peers
   */
  private _server: net.Server;

  /**
   * @param port The port on which this TCP server should listen for incoming connections.
   * This port must not already be in use on this computer.
   */
  constructor(port: number) {
    this._port = port;
    this._peerIdCounter = 0;
    // Setup the TCP server for handling incoming OpenSpace connections
    this._server = net.createServer();

    this._server.on('connection', (socket: net.Socket) => {
      LDEBUG('New connection', socket.remoteAddress);

      // The Peer is only added to the list if the authentication is succesful.
      // eslint-disable-next-line prefer-const
      let peer: Peer = {
        id: this._peerIdCounter, // TODO: assign a unique ID, see comment in ´onEnd´
        name: '',
        socket: socket,
        status: ConnectionStatus.Connecting,
        sessionName: ''
      };

      socket.on('data', (data: Buffer) => {
        this.onData(data, peer);
      });
      socket.on('end', () => {
        this.onEnd(peer);
      });
      socket.on('error', (error) => {
        LERROR(`Error: ${error} from peer ${peer.id}`);
        this.onEnd(peer);
      });
    });
  }

  /**
   * Starts the TCP server and begins accepting incoming connections.
   *
   * @return A promise that resolves to true once the server is listening,
   *         or rejects with an error if the port is unavailable.
   */
  public start(): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      this._server.on('listening', () => {
        LINFO(`Wormhole listening on port ${this._port}`);
        resolve(true);
      });

      this._server.on('error', (error: Error) => {
        this._server.close();
        LERROR(`Error starting server: ${error.message}`);
        reject(error);
      });

      this._server.listen(this._port);
    });
  }

  /**
   * Creates and registers a new session. If a session with the same name already
   * exists it is removed first (this should not normally happen).
   *
   * @return The newly created Session
   */
  public async addSession(
    name: string,
    password: string | null,
    hostPassword: string,
    id: string | null = null
  ): Promise<Session> {
    // If the session already exists, remove it (this *should* not happen)
    if (name in this._sessions) {
      const oldSession = this._sessions[name];
      await this.removeSession(oldSession.getSessionMetadata().id!);
    }

    const session = new Session(name, password, hostPassword, id);
    this._sessions[name] = session;
    return session;
  }

  /**
   * @return The number of active sessions currently running
   */
  public activeSessions(): number {
    return Object.keys(this._sessions).length;
  }

  /**
   * Removes a session by ID or by Session object reference. Disconnects all peers before
   * removing from the internal registry. Resolves once all peers have been disconnected.
   *
   * @param sessionIdOrSession The session ID string, or the Session object directly
   * @return A promise that resolves with a success message, or rejects on error
   */
  public async removeSession(sessionIdOrSession: string | Session): Promise<string> {
    const session =
      typeof sessionIdOrSession === 'string'
        ? Object.values(this._sessions).find((session: Session) => {
            return session.getSessionMetadata().id === sessionIdOrSession;
          })
        : sessionIdOrSession;

    if (!session) {
      throw new Error('Session not found');
    }

    const { id, sessionName } = session.getSessionMetadata();
    try {
      // Notify all peers that the session is closing
      await session.stop();
      // Remove session from internal registry
      delete this._sessions[sessionName];

      const msg = `Session '${id ?? sessionName}' successfully removed`;
      LDEBUG(msg);
      return msg;
    } catch (error) {
      const errorMsg = `Error stopping session "${sessionIdOrSession}": ${(error as Error).message}`;
      LERROR(errorMsg);
      throw error;
    }
  }

  /**
   * Handles incoming data packages on the socket. We unpack the message and bail early
   * if there are any errors in the provided message. A valid message is then forwarded
   * to the appropriate handlers.
   *
   * @param data The data package that was received on the socket
   * @param peer The Peer from which this message arrived
   */
  private onData(data: Buffer, peer: Peer): void {
    const HeaderSize =
      'OS'.length + // OS prefix
      Uint8Array.BYTES_PER_ELEMENT + // protocol version number
      Uint8Array.BYTES_PER_ELEMENT + // message type identifier
      Uint32Array.BYTES_PER_ELEMENT; // payload size in bytes

    // Exit early if we don't have a valid header information
    if (data.length < HeaderSize) {
      LDEBUG('Invalid header information');
      return;
    }

    const prefix = data.subarray(0, 2).toString('utf-8');
    if (prefix !== 'OS') {
      LDEBUG(`The message did not start with OS prefix, invalid message: '${prefix}'`);
      return;
    }

    const dv = new DataView(
      data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
    );

    let offset = 'OS'.length;
    const protocolVersion = dv.getUint8(offset);
    offset += Uint8Array.BYTES_PER_ELEMENT;
    if (protocolVersion !== CurrentProtocolVersion) {
      LDEBUG(
        `Invalid protocol version: '${protocolVersion}', expected: '${CurrentProtocolVersion}'`
      );
      return;
    }

    const messageType = dv.getUint8(offset);
    offset += Uint8Array.BYTES_PER_ELEMENT;
    if (!(messageType in MessageType)) {
      LDEBUG(`Invalid message type: '${messageType}'`);
      return;
    }

    const messageSize = dv.getUint32(offset, true);
    offset += Uint32Array.BYTES_PER_ELEMENT;
    if (data.byteLength !== offset + messageSize) {
      LDEBUG('The provided message size was not the same as the actual message length');
      LDEBUG(`Received message type: ${toString(messageType)}`);
      LDEBUG(`Header size: ${HeaderSize}`);
      LDEBUG(`Data size: ${data.byteLength}`);
      LDEBUG(`Data byteoffset: ${data.byteOffset}`);
      LDEBUG(`Message size: ${messageSize}`);
      LDEBUG(`Offset: ${offset}`);
      return;
    }

    // Slice the header data from the message
    const messagePayload = data.subarray(offset);

    switch (messageType) {
      case MessageType.Authentication:
        this.handleAuthentication(messagePayload, peer);
        break;
      case MessageType.Data:
        this.handleData(messagePayload, peer);
        break;
      case MessageType.HostshipRequest:
        this.handleHostshipRequest(messagePayload, peer);
        break;
      case MessageType.HostshipResignation:
        this.handleHostshipResignation(messagePayload, peer);
        break;
    }
  }

  /**
   * Handles the disconnection of a peer. We remove the Peer from the list of connected
   * peers and free up the ID slot. If the Peer that disconnected was the host, we
   * inform all connected peers that they no longer have a host.
   *
   * TODO: Currently we assign the ID of a connected peer by the length of the array of
   * connected peers. If there are 2 peers connected and the first one disconnects and
   * then reconnects, both peers will end up with ID = 1.
   *
   * @param peer The Peer that just disconnected
   */
  private onEnd(peer: Peer): void {
    LDEBUG(`Peer ${peer.id} disconnected, closing connection`);
    // Get the session that the peer is connected to
    const session = this._sessions[peer.sessionName];

    if (!session) {
      LDEBUG(`Session "${peer.sessionName}" not found`);
      return;
    }

    session.onEnd(peer);
  }

  /**
   * Handles the incoming authentication method by the provided peer. If the
   * authentication is valid and contains the correct password, the peer is added to the
   * list in the group. If the host password is also correct and there is no currently
   * assigned host, the peer is automatically promoted to hostship too.
   *
   * @param data The payload of the authentication message
   * @param peer The Peer from which this message arrived
   */
  private handleAuthentication(data: Buffer, peer: Peer): void {
    LDEBUG(`Handling authentication for peer ${peer.id}`);

    const dv = new DataView(
      data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
    );

    let offset = 0;
    const passwordLength = dv.getUint16(offset, true);
    offset += Uint16Array.BYTES_PER_ELEMENT;
    const password =
      passwordLength === 0
        ? ''
        : data.subarray(offset, offset + passwordLength).toString('utf-8');
    offset += passwordLength;

    const hostPasswordLength = dv.getUint16(offset, true);
    offset += Uint16Array.BYTES_PER_ELEMENT;
    const hostPassword =
      hostPasswordLength === 0
        ? ''
        : data.subarray(offset, offset + hostPasswordLength).toString('utf-8');
    offset += hostPasswordLength;

    const sessionNameLength = dv.getUint8(offset);
    offset += Uint8Array.BYTES_PER_ELEMENT;
    const sessionName = data
      .subarray(offset, offset + sessionNameLength)
      .toString('utf-8');
    offset += sessionNameLength;
    peer.sessionName = sessionName;

    const nameLength = dv.getUint8(offset);
    offset += Uint8Array.BYTES_PER_ELEMENT;
    peer.name =
      nameLength === 0
        ? 'Anonymous'
        : data.subarray(offset, offset + nameLength).toString('utf-8');

    // Get the session that this peer is trying to connect to
    const session = this._sessions[sessionName];
    if (!session) {
      LDEBUG(`No session with name '${sessionName}' found`);
      return;
    }

    const authenticated = session.handleAuthentication(peer, password, hostPassword);
    if (authenticated) {
      this._peerIdCounter++;
    }
  }

  /**
   * Handle incoming data from the provided peer, we only forward the data along to
   * other peers if it comes from the host.
   *
   * @param data The payload of the data message
   * @param peer The Peer from which this message is coming
   */
  private handleData(data: Buffer, peer: Peer): void {
    const session = this._sessions[peer.sessionName];
    if (!session) {
      LDEBUG(`No session with name '${peer.sessionName}' found`);
      return;
    }
    session.handleData(data, peer);
  }

  /**
   * Handles an incoming hostship request message by the peer. If the message contains
   * the correct host password, the peer is promoted to hostship and the previous host
   * is demoted (if there was one).
   *
   * @param data The payload of the hostship request message
   * @param peer The Peer from which this message arrived
   */
  private handleHostshipRequest(data: Buffer, peer: Peer): void {
    const session = this._sessions[peer.sessionName];
    if (!session) {
      LDEBUG(`No session with name '${peer.sessionName}' found`);
      return;
    }

    session.handleHostshipRequest(data, peer);
  }

  /**
   * Handles an incoming hostship resignation by the peer. If the peer is the current
   * host, we remove the hostship and inform all connected peers that they lost their
   * host.
   *
   * @param _ Unused parameter
   * @param peer The Peer from which this message arrived
   */
  private handleHostshipResignation(_: Buffer, peer: Peer): void {
    const session = this._sessions[peer.sessionName];
    if (!session) {
      LDEBUG(`No session with name '${peer.sessionName}' found`);
      return;
    }
    session.handleHostshipResignation(peer);
  }
}
