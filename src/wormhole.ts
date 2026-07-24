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

import * as net from 'net';

import {
  ConnectionStatus,
  CurrentProtocolVersion,
  MessageType,
  Peer
} from './types/types';
import { Session } from './session';
import { LDEBUG, LERROR, LINFO } from './utils';

const NeedMoreData = 0;
const ProtocolError = -1;

/**
 * A TCP server that listens on a single port and routes incoming OpenSpace connections
 * into their respective named sessions. Manages the full lifecycle of all active
 * sessions.
 */
export class Wormhole {
  // The port on which this TCP server is listening
  private _port: number;

  // A global id that is assigned to connected peers, regardless of session they belong
  // to
  private _peerIdCounter: number;

  // All sessions currently managed by this Wormhole, keyed by session name
  private _sessions: { [name: string]: Session } = {};

  // The local TCP server that is listening for incoming OpenSpace connections to the
  // different sessions
  private _server: net.Server;

  /**
   * @param port The port on which this TCP server should listen for incoming connections.
   *             This port must not already be in use on this computer
   */
  constructor(port: number) {
    this._port = port;
    this._peerIdCounter = 0;
    // Setup the TCP server for handling incoming OpenSpace connections
    this._server = net.createServer();

    this._server.on('connection', (socket: net.Socket) => {
      LDEBUG(`Wormhole: new connection from ${socket.remoteAddress}`);
      socket.setNoDelay(true);

      // The peer is only added to the list if the authentication is successful. Note: the
      // `Id` is assigned once authentication is attempted, see `handleAuthentication`
      const peer: Peer = {
        id: -1,
        name: '',
        socket: socket,
        status: ConnectionStatus.Connecting,
        sessionName: '',
        buffer: Buffer.alloc(0)
      };

      socket.on('data', (data: Buffer) => {
        this.onData(data, peer);
      });
      socket.on('end', () => {
        this.onEnd(peer);
      });
      socket.on('error', (error) => {
        LERROR(`Peer #${peer.id}: socket error`, error);
        this.onEnd(peer);
      });
    });
  }

  /**
   * Starts the TCP server and begin accepting incoming connections.
   *
   * @return A promise that resolves to true once the server is listening, or rejects with
   *         an error if the port is unavailable.
   */
  public start(): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      this._server.on('listening', () => {
        LINFO(`Wormhole: listening on port ${this._port}`);
        resolve(true);
      });

      this._server.on('error', (error: Error) => {
        this._server.close();
        LERROR(`Wormhole: failed to start server `, error);
        reject(error);
      });

      this._server.listen(this._port);
    });
  }

  /**
   * Creates and registers a new session. If a session with the same name already exists
   * it is removed first (this should not normally happen).
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
      await this.removeSession(oldSession);
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
      throw new Error(`Wormhole: session '${sessionIdOrSession}' not found`);
    }

    const { id, sessionName } = session.getSessionMetadata();
    try {
      // Notify all peers that the session is closing
      await session.stop();
      // Remove session from internal registry
      delete this._sessions[sessionName];
      LDEBUG(`Wormhole: session '${id ?? sessionName}' removed`);
      return `Session '${id ?? sessionName}' successfully removed`;
    } catch (error) {
      LERROR(`Wormhole: session '${id ?? sessionName}' failed to stop`, error);
      throw error;
    }
  }

  /**
   * Handles incoming raw bytes from the peer's socket. TCP gives no guarantee that a
   * single 'data' event aligns with a single application-level message, i.e., a message
   * can arrive split across several events, or several messages can arrived coalesced
   * into one event.
   *
   * @param data The data package that was received on the socket
   * @param peer The Peer from which this message arrived
   */
  private onData(data: Buffer, peer: Peer): void {
    peer.buffer = peer.buffer.length === 0 ? data : Buffer.concat([peer.buffer, data]);

    // Keep extracting messages for as long as the buffer holds a complete one
    let consumed = this.processMessage(peer);
    while (consumed > NeedMoreData) {
      peer.buffer = peer.buffer.subarray(consumed);
      consumed = this.processMessage(peer);
    }

    if (consumed === ProtocolError) {
      LDEBUG(`Peer #${peer.id}: connection terminated after protocol error`);
    }
  }

  /**
   * Attempts to parse and dispatch a single complete message from the front of
   * `peer.buffer`. If the buffer does not yet hold a full header, or a full header plus
   * its payload, no action is taken. If the header is malformed, the stream is considered
   * unrecoverable.
   *
   * @param peer The Peer whose buffer should be parsed
   * @return The number of bytes (header + payload) consumed from the front of the buffer.
   *         Return `NeedMoreData` if no complete message could be extracted, which
   *         happens because more data is still needed or `ProtocolError` if the
   *         connection was just terminated due to a protocol error
   */
  private processMessage(peer: Peer): number {
    const HeaderSize =
      'OS'.length + // OS prefix
      Uint8Array.BYTES_PER_ELEMENT + // Protocol version number
      Uint8Array.BYTES_PER_ELEMENT + // Message type identifier
      Uint32Array.BYTES_PER_ELEMENT; // Payload size in bytes

    const { buffer } = peer;

    if (buffer.length < HeaderSize) {
      return NeedMoreData; // Header hasn't fully arrived yet
    }

    // Check the prefix matches 'OS'
    if (buffer[0] !== 0x4f || buffer[1] !== 0x53) {
      LERROR(
        `Peer #${peer.id}: stream desynced, expected 'OS' prefix, got ` +
          `'${buffer.subarray(0, 2).toString('utf-8')}'`
      );
      peer.socket.destroy(new Error('Protocol desync'));
      return ProtocolError;
    }

    const dv = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    let offset = 'OS'.length;

    const protocolVersion = dv.getUint8(offset);
    offset += Uint8Array.BYTES_PER_ELEMENT;
    if (protocolVersion !== CurrentProtocolVersion) {
      LERROR(`Peer #${peer.id}: invalid protocol version '${protocolVersion}'`);
      peer.socket.destroy(new Error('Protocol version mismatch'));
      return ProtocolError;
    }

    const messageType = dv.getUint8(offset);
    offset += Uint8Array.BYTES_PER_ELEMENT;
    if (!(messageType in MessageType)) {
      LERROR(`Peer #${peer.id}: invalid message type '${messageType}'`);
      peer.socket.destroy(new Error('Invalid message type'));
      return ProtocolError;
    }

    const payloadSize = dv.getUint32(offset, true);
    offset += Uint32Array.BYTES_PER_ELEMENT;

    const MaxPayloadSize = 128000; // 128 kb limit
    if (payloadSize > MaxPayloadSize) {
      LERROR(`Peer #${peer.id}: payload too large (${payloadSize} bytes)`);
      peer.socket.destroy(new Error('Payload too large'));
      return ProtocolError;
    }

    const messageSize = offset + payloadSize;

    if (buffer.byteLength < messageSize) {
      return NeedMoreData; // Payload hasn't fully arrived yet
    }

    try {
      // Slice the header data from the message
      const messagePayload = buffer.subarray(offset, messageSize);

      // Dispatch message
      switch (messageType) {
        // Session name is parsed from the payload during authentication
        case MessageType.Authentication: {
          const status = this.handleAuthentication(messagePayload, peer);
          if (status.authenticated) {
            return messageSize;
          } else {
            peer.socket.destroy(new Error(status.message));
            return ProtocolError;
          }
        }
        default:
      }

      // All other message types require the peer to already be registered in a session
      const session = this._sessions[peer.sessionName];
      if (!session) {
        LERROR(`Wormhole: session '${peer.sessionName}' not found`);
        peer.socket.destroy(
          new Error(`Could not find session with name '${peer.sessionName}'`)
        );
        return ProtocolError;
      }

      switch (messageType) {
        case MessageType.Data:
          session.handleData(messagePayload, peer);
          break;
        case MessageType.HostshipRequest:
          session.handleHostshipRequest(messagePayload, peer);
          break;
        case MessageType.HostshipResignation:
          session.handleHostshipResignation(peer);
          break;
        default:
          LERROR(`Peer #${peer.id}: Unhandled messageType (${messageType})`);
          peer.socket.destroy(new Error('Unhandled message type'));
          return ProtocolError;
      }
    } catch (error) {
      LERROR(`Peer #${peer.id}: malformed payload: ${error}`);
      peer.socket.destroy(new Error('Malformed payload'));
      return ProtocolError;
    }

    return messageSize;
  }

  /**
   * Handles the disconnection of a peer.
   *
   * @param peer The Peer that just disconnected
   */
  private onEnd(peer: Peer): void {
    LDEBUG(`Peer #${peer.id}: disconnected, closing connection`);
    // Get the session that the peer is connected to
    const session = this._sessions[peer.sessionName];

    if (!session) {
      LDEBUG(`Wormhole: session '${peer.sessionName}' not found`);
      return;
    }

    session.onEnd(peer);
  }

  /**
   * Handles the incoming authentication method by the provided peer. If the
   * authentication is valid and contains the correct password, the peer is added to the
   * list in the session. If the host password is also correct and there is currently no
   * assigned host, the peer is automatically promoted to hostship too.
   *
   * @param data The payload of the authentication message
   * @param peer The Peer from which this message arrived
   * @return An object containing the authentication status (true if authentication
   *         succeedes, false otherwise) and an optional message
   */
  private handleAuthentication(
    data: Buffer,
    peer: Peer
  ): { authenticated: boolean; message?: string } {
    LDEBUG(`Wormhole: handling authentication attempt from ${peer.socket.remoteAddress}`);

    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);

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
        ? null
        : data.subarray(offset, offset + hostPasswordLength).toString('utf-8');
    offset += hostPasswordLength;

    const sessionNameLength = dv.getUint8(offset);
    offset += Uint8Array.BYTES_PER_ELEMENT;
    const sessionName = data
      .subarray(offset, offset + sessionNameLength)
      .toString('utf-8');
    offset += sessionNameLength;
    if (!/^[\x00-\x7F]*$/.test(sessionName)) {
      return { authenticated: false, message: 'Invalid session name (must be ASCII)' };
    }
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
      LDEBUG(`Wormhole: session '${sessionName}' not found`);
      return { authenticated: false, message: `Session '${sessionName}': not found` };
    }

    if (!session.getSessionMetadata().id) {
      LERROR(
        `Wormhole: session '${sessionName}' has no ID set when peer ` +
          `'${peer.socket.remoteAddress} tried to connect`
      );
      return {
        authenticated: false,
        message: 'Missing session ID, session not ready yet, please try again later'
      };
    }

    if (!session.isPasswordValid(password)) {
      LDEBUG(`Wormhole: session '${sessionName}' invalid password provided`);
      return {
        authenticated: false,
        message: `Invalid password`
      };
    }

    peer.id = this._peerIdCounter++;
    session.registerPeer(peer, hostPassword);
    return { authenticated: true };
  }
}
