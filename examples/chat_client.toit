// Copyright (C) 2021 Toitware ApS.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the EXAMPLES_LICENSE file.

import http
import net
import websocket

main:
  network := net.open
  client := http.Client network
  session := websocket.Session.connect client "localhost:8081" "/ws"

  task::
    while msg := session.receive:
      print "reply: $msg"
    print "<closed>"

  session.send "lala"
