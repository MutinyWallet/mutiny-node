use serde::{Deserialize, Serialize};

/// MutinyProxyCommand are proxy commands that get sent to/from
/// the clients to/from the proxy.
///
/// Disconnect:
/// The proxy uses this to inform a client that one of the peers
/// that they were connected to has gone away.
/// The clients should use this to inform the proxy that they are
/// asking to be disconnected to one of the peers that they are
/// currently connected to. The proxy will send the other peer
/// the `Disconnect` message afterwards.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum MutinyProxyCommand {
    Disconnect { to: Vec<u8>, from: Vec<u8> },
}

#[cfg(test)]
mod tests {
    use crate::MutinyProxyCommand;

    #[test]
    fn test_deserialization() {
        assert_eq!(
            serde_json::from_str::<MutinyProxyCommand>(
                "{\"Disconnect\":{\"to\":[1,1],\"from\":[10,10]}}"
            )
            .unwrap(),
            MutinyProxyCommand::Disconnect {
                to: vec![1, 1],
                from: vec![10, 10]
            }
        )
    }

    #[test]
    fn test_serialization() {
        assert_eq!(
            "{\"Disconnect\":{\"to\":[1,1],\"from\":[10,10]}}",
            serde_json::to_string(&MutinyProxyCommand::Disconnect {
                to: vec![01, 01],
                from: vec![10, 10]
            })
            .unwrap()
        )
    }
}
