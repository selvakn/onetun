pub mod tcp;

use crate::config::PortProtocol;
use async_trait::async_trait;
use std::fmt::{Display, Formatter};

#[async_trait]
pub trait VirtualInterfacePoll {
    async fn poll_loop(mut self) -> anyhow::Result<()>;
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct VirtualPort(pub u16, pub PortProtocol);

impl Display for VirtualPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}:{}]", self.0, self.1)
    }
}
