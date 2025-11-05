# example to prevent specific filetypes from being uploaded via ftp
when RULE_INIT {
  set DEBUG 1
}

when CLIENT_ACCEPTED {
  if { $::DEBUG } { log local0. "client accepted" }
}

when CLIENT_DATA {
  if { $::DEBUG } { log local0. "----------------------------------------------------------" }
  if { $::DEBUG } { log local0. "payload [TCP::payload]" }
  set client_data [string trim [TCP::payload]]
  #---------------------------------------------------
  # Block or alert specific commands
  #---------------------------------------------------
  switch -glob [string tolower $client_data] {
    "stor *.tar" -
    "stor *.gz" -
    "stor *.tgz" -
    "stor *.tar.gz" -
    "stor *.zip" {
      if { $::DEBUG } { log local0. "LOG: STOR request detected" }
      
      TCP::respond "550 STOR filetype not allowed\r\n"
      TCP::payload replace 0 [string length $client_data] ""
      return
    }
  }      
  TCP::release
  TCP::collect
}

when SERVER_CONNECTED {
  if { $::DEBUG } { log "server connected" }
  TCP::release
  TCP::collect
  clientside { TCP::collect }
}
when SERVER_DATA {
  if { $::DEBUG } { log local0. "payload <[TCP::payload]>" }
  TCP::release
  TCP::collect
}

when CLIENT_CLOSED {
  if { $::DEBUG } { log local0. "client closed" }
}
