import { Socket } from 'net';

export type SessionData = {
  id: string;
  active: boolean;
  inactiveTimeStamp: number;
  created: number;
  usage: number;
  password: string | null;
  nPeers: number;
  currentHost: string;
  roomName: string;
  profile: string;
  isPrivate: boolean;
  owner: string | null;
};

export type SessionHistoryData = {
  id: string;
  inactiveTimeStamp: number;
  created: number;
  uptime: number;
  usage: number;
  roomName: string;
  owner: string | null;
};

export type StatisticData = {
  nPeers: number;
  timestamp: number;
};

export const CurrentProtocolVersion = 7;

export enum MessageType {
  Authentication = 0,
  Data,
  ConnectionStatus,
  HostshipRequest,
  HostshipResignation,
  NConnections
}

export enum ConnectionStatus {
  Disconnected = 0,
  Connecting,
  ClientWithoutHost,
  ClientWithHost,
  Host
}

export type Peer = {
  /**
   * A unique ID for this peer
   */
  id: number;

  /**
   * The user-provided name for this peer, or "Anonymous" if no name was specified. The
   * name can have a maximum length of 255 characters and can only consist of ASCII
   * characters
   */
  name: string;

  /**
   * The socket on which to contact the Peer and send messages to
   */
  socket: Socket;

  /**
   * The connection status of this peer
   */
  status: ConnectionStatus;

  /**
   * The name of the session this peer is connected to
   */
  sessionName: string;
};
