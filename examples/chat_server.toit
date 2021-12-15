// Copyright (C) 2021 Toitware ApS.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the EXAMPLES_LICENSE file.

import http
import net
import websocket

main:
  sessions := {:}

  network := net.open
  server := http.Server
  server.listen network 8081:: | request/http.Request response/http.ResponseWriter |
    session := websocket.Session.upgrade request response

    task::
      peer_address := session.peer_address
      sessions[peer_address] = session
      while msg := session.receive:
        sessions.do --values: it.send msg
      sessions.remove peer_address
