//// Stands in for a database table of remembered logins. It is kept in memory
//// so the demo has nothing to set up, which means a restart forgets everyone.

import gleam/dict.{type Dict}
import gleam/erlang/process.{type Subject}
import gleam/otp/actor
import gleam/result

pub opaque type Store {
  Store(subject: Subject(Message))
}

type Message {
  Remember(login_identifier: String, user: String, reply_to: Subject(Nil))
  Find(login_identifier: String, reply_to: Subject(Result(String, Nil)))
  Forget(login_identifier: String, reply_to: Subject(Nil))
}

const timeout_milliseconds: Int = 1000

pub fn start() -> Result(Store, actor.StartError) {
  actor.new(dict.new())
  |> actor.on_message(handle_message)
  |> actor.start
  |> result.map(fn(started) { Store(started.data) })
}

pub fn remember(store: Store, login_identifier: String, user: String) -> Nil {
  actor.call(store.subject, timeout_milliseconds, Remember(
    login_identifier,
    user,
    _,
  ))
}

/// The user a login identifier belongs to, unless it was never stored or has been
/// forgotten.
pub fn find(store: Store, login_identifier: String) -> Result(String, Nil) {
  actor.call(store.subject, timeout_milliseconds, Find(login_identifier, _))
}

pub fn forget(store: Store, login_identifier: String) -> Nil {
  actor.call(store.subject, timeout_milliseconds, Forget(login_identifier, _))
}

fn handle_message(
  logins: Dict(String, String),
  message: Message,
) -> actor.Next(Dict(String, String), Message) {
  case message {
    Remember(login_identifier:, user:, reply_to:) -> {
      process.send(reply_to, Nil)
      actor.continue(dict.insert(logins, login_identifier, user))
    }
    Find(login_identifier:, reply_to:) -> {
      process.send(reply_to, dict.get(logins, login_identifier))
      actor.continue(logins)
    }
    Forget(login_identifier:, reply_to:) -> {
      process.send(reply_to, Nil)
      actor.continue(dict.delete(logins, login_identifier))
    }
  }
}
