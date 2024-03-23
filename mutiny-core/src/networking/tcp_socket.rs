use crate::error::MutinyError;
use crate::networking::socket::ReadDescriptor;
use crate::utils;
use lightning::ln::peer_handler;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::{hash::Hash, io::Read};
use std::{io::Write, net::TcpStream};

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct TcpSocketDescriptor {
    conn: Arc<Mutex<TcpStream>>,
    id: u64,
}

impl TcpSocketDescriptor {
    pub fn new(conn: Arc<Mutex<TcpStream>>) -> Self {
        let id = ID_COUNTER.fetch_add(1, Ordering::AcqRel);
        Self { conn, id }
    }
}

impl ReadDescriptor for TcpSocketDescriptor {
    async fn read(&self) -> Option<Result<Vec<u8>, MutinyError>> {
        let mut buf = [0; 4096];
        match self.conn.lock().unwrap().read(&mut buf) {
            Ok(_) => Some(Ok(buf.to_vec())),
            Err(_) => Some(Err(MutinyError::ConnectionFailed)),
        }
    }
}

impl peer_handler::SocketDescriptor for TcpSocketDescriptor {
    fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
        let cloned_data = Vec::from(data);
        let cloned_conn = self.conn.clone();
        let mut write = cloned_conn.lock().unwrap();
        match write.write(&cloned_data) {
            Ok(_) => {}
            Err(_e) => {
                // TODO log?
            }
        }
        data.len()
    }

    fn disconnect_socket(&mut self) {
        // socket will be closed when dropped
    }
}
impl Clone for TcpSocketDescriptor {
    fn clone(&self) -> Self {
        Self {
            conn: Arc::clone(&self.conn),
            id: self.id,
        }
    }
}
impl Eq for TcpSocketDescriptor {}
impl PartialEq for TcpSocketDescriptor {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id
    }
}
impl Hash for TcpSocketDescriptor {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl std::fmt::Debug for TcpSocketDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "({})", self.id)
    }
}
