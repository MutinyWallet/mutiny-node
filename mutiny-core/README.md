# mutiny-core

The core SDK for the mutiny node.

```bash
cargo add mutiny-core
```

### Usage

```rust
use bitcoin::Network;
use mutiny_core::nodemanager::NodeManager;

async fn main() {
    let nm = NodeManager::new(
        "password".to_string(),
        None,
        None,
        Some(Network::Testnet),
        None,
        None,
        None,
    ).await.unwrap();

    let address = nm.get_new_address().await.unwrap();
    println!("Address: {}", address);

    let tx_details_opt = nm.check_address(address).await.unwrap();
}

```