# Wormhole - Parallel Connection
# Overview
The web app enhances the usability of Parallel Connection in OpenSpace by enabling users to view available rooms (sessions), create and share rooms with others, and join sessions directly from the website if OpenSpace is running locally.

# Functionality
### Session Information
View detailed information about each session, including the number of participants, the creator of the room, the current host, and other relevant information.

### Join Existing Rooms
Easily connect to an existing room session via the website if you're connected to OpenSpace.

### Share Room
Share room links with others for automatic joining and seamless streaming.

### Create New Rooms
All sessions occupied? Log in with your Google, Facebook, Twitter, or GitHub account and create a new session.

# Wormhole
To start the Wormhole server locally, you will need [Node.JS and NPM](https://nodejs.org) installed on your system. With that taken care of

1. Clone this repository and enter the `Wormhole` folder
1. Install all potentially required packages by calling `npm install`
1. Make a copy of `.env_sample`, rename it to `.env` and fill in the information. The projects API keys can be found on [Firebase](https://console.firebase.google.com/u/0/), download the projects admin sdk files as well.
  - API
    1. In the Firebase console, open `Project Overview` > `1 app` > `Cog wheel`
    1. Scroll down to see the values
  - Admin SDK
    1. In the Firebase console, open `Settings` > `Service Accounts`.
    1. Click `Generate New Private Key`, then confirm by clicking `Generate Key`.
    1. Securely store the JSON file containing the key.

1. Start the frontend and backend server by executing `npm run dev`. This will set up all the neccesary processes that will transpile the necessary files, enable hot reload, and serve a local express app.
1. To ready the app for deployment execute `npm run build`. This will build both the frontend and backend into `.local/express` and `.local/vite`.
1. Optionally you can run only the frontend by executing `npm run vite:dev` or only the backend by executing `npm run api:dev`.

# Message Structures (version 7)
This section describes the different message types that are being sent between OpenSpace and the Wormhole application. A message consists of a header and a type-appropriate payload.

```cpp
struct {
  byte[2] header; // fixed header, must be equal to "OS"
  uint8_t version; // The version of the protocol. Must be 7
  uint8_t messageType; // The type of the message that is contained in the payload
  uint32_t messageSize; // The total size of the payload data
  byte[messageSize] payload; // The payload of the message according to the messageType
}
```


## Authentication (Type = 0)
This message is sent from OpenSpace to the Wormhole server to authenticate a new peer to a running session. It consists of a password which has to be provided, and an optional host password, and the optional name. An optional parameter is represented by a length of 0.

```cpp
struct {
  uint16_t passwordLength; // The length of the password field
  byte[passwordLength] password; // The provided password without a terminating \0
  uint16_t hostPasswordLength; // The length of the host password field or 0 if the host password is omitted
  byte[hostPasswordLength] hostPassword; // The host password
  uint8_t roomNameLength; // The length of the session room name field
  byte[roomNameLength] roomName; // The session room name
  uint8_t nameLength; // The length of the user's name or 0 if the name is omitted
  byte[nameLength] name; // The users's name
}
```

## Data (Type = 1)
This type of message is sent from the host Peer to the Wormhole server which then distributes this message to all other connected peers. This message is the primary way method for the host to send OpenSpace related data to the connected peers. Only the host of the session should send these messages to the Wormhole server.

```cpp
struct {
  enum : uint8_t {
    Camera = 0,
    Time = 1,
    Script = 2
  } dataType; // The type of data message that is being sent

  double timestamp; // A monotonously increasing timestamp used to uniquely order the data messages on the receiving end

  byte[*] payload; // The content of the data message. The length of this payload is fixed for each of the `dataTypes` and described below
}
```

### Camera
This data message contains information about the current camera

```cpp
struct {
  double[3] position; // The position of the camera
  double[4] rotation; // The orientation of the camera expressed as a quaternion
  uint8_t followNodeRotation; // A boolean expressing whether the camera is following the rotation of the current focus node. Only values 0 and 1 are allowed
  uint32_t nodeNameLength; // The length of the name of the current focus node
  byte[nodeNameLength] focusNode; // The name of the current focus node
  float scale; // The current camera scale applied to the entire scene
  double timestamp; // The timestamp of the message
}
```

### Time
This data message contains information about the current in-game time.

```cpp
struct {
  double time; // The current in-game time
  double dt; // The current simulation increment
  uint8_t isPaused; // Determines whether the current simulation time is paused. Only values 0 and 1 are allowed
  uint8_t requiresTimeJump; // This value is 1 if the current `time` is far different from the `dt` + the `time` of the previous message. Otherwise it is 0
  double timestamp; // The timestamp of the message
}
```

### Script
This data message contains a Lua script that the host wants a peer to be executed.

```cpp
struct {
  uint32_t scriptLength; // The length of the script message
  byte[scriptLength] script; // The contents of the script
}
```

## ConnectionStatus (Type = 2)
This message is sent from the Wormhole server to OpenSpace to inform the Peer about a change in status, be it the Peer's status or if the host of the session has changed.

```cpp
struct {
  enum : uint8_t {
    Disconnected = 0,
    Connecting = 1,
    ClientWithoutHost = 2,
    ClientWithHost = 3,
    Host = 4
  } status;  // The identifier of the status

  uint8_t hostNameLength; // The number of characters of the new host or 0 if there is no host
  byte[hostNameLength] hostName; // The name of the current host of the session
}
```

## HostshipRequest (Type = 3)
This message is sent from OpenSpace to the Wormhole server when the Peer signals that it wants to become the active host.

```cpp
struct {
  uint16_t passwordLength; // The length of the password field
  byte[passwordLength] password; // The password
}
```

## HostshipResignation (Type = 4)
This message is sent from OpenSpace to the Wormhole server when the Peer signals that it wants to resign a potentially current hostship.

```cpp
struct {
  // No fields sent in the payload of the message
}
```

## NConnections (Type = 5)
This message is sent from the Wormhole server to OpenSpace to inform the peer about a changed number of total connected peers to the server.

```cpp
struct {
  uint32_t nConnection; // The number of total peers connected to the server
}
```
