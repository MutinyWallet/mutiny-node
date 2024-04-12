use nostr::{Event, EventBuilder, EventId, Filter, PublicKey, SubscriptionId};
use nostr_sdk::client::Error;
use nostr_sdk::{NostrSigner, SubscribeAutoCloseOptions};
use std::time::Duration;

#[cfg_attr(test, mockall::automock)]
pub trait NostrClient {
    async fn add_relays(&self, relays: Vec<String>) -> nostr::Result<(), Error>;
    async fn add_relay(&self, relay: &str) -> nostr::Result<bool, Error>;
    async fn connect_relay(&self, relay: &str) -> nostr::Result<(), Error>;
    async fn connect(&self);
    async fn disconnect(&self) -> nostr::Result<(), Error>;

    async fn sign_event_builder(&self, builder: EventBuilder) -> nostr::Result<Event, Error>;
    async fn send_event_builder(&self, builder: EventBuilder) -> nostr::Result<EventId, Error>;
    async fn send_event(&self, event: Event) -> nostr::Result<EventId, Error>;
    async fn send_event_to(&self, urls: Vec<String>, event: Event)
        -> nostr::Result<EventId, Error>;
    async fn send_direct_msg(
        &self,
        receiver: PublicKey,
        msg: String,
        reply_to: Option<EventId>,
    ) -> nostr::Result<EventId, Error>;

    async fn subscribe(
        &self,
        filters: Vec<Filter>,
        opts: Option<SubscribeAutoCloseOptions>,
    ) -> SubscriptionId;
    async fn get_events_of(
        &self,
        filters: Vec<Filter>,
        timeout: Option<Duration>,
    ) -> Result<Vec<Event>, Error>;

    async fn set_signer(&self, signer: Option<NostrSigner>);
}

impl NostrClient for nostr_sdk::Client {
    async fn add_relays(&self, relays: Vec<String>) -> nostr::Result<(), Error> {
        self.add_relays(relays).await
    }

    async fn add_relay(&self, relay: &str) -> nostr::Result<bool, Error> {
        self.add_relay(relay).await
    }

    async fn connect_relay(&self, relay: &str) -> nostr::Result<(), Error> {
        self.connect_relay(relay).await
    }

    async fn connect(&self) {
        self.connect().await
    }

    async fn disconnect(&self) -> nostr::Result<(), Error> {
        self.disconnect().await
    }

    async fn sign_event_builder(&self, builder: EventBuilder) -> nostr::Result<Event, Error> {
        self.sign_event_builder(builder).await
    }

    async fn send_event_builder(&self, builder: EventBuilder) -> nostr::Result<EventId, Error> {
        self.send_event_builder(builder).await
    }

    async fn send_event(&self, event: Event) -> nostr::Result<EventId, Error> {
        self.send_event(event).await
    }

    async fn send_event_to(
        &self,
        urls: Vec<String>,
        event: Event,
    ) -> nostr::Result<EventId, Error> {
        self.send_event_to(urls, event).await
    }

    async fn send_direct_msg(
        &self,
        receiver: PublicKey,
        msg: String,
        reply_to: Option<EventId>,
    ) -> nostr::Result<EventId, Error> {
        self.send_direct_msg(receiver, msg, reply_to).await
    }

    async fn subscribe(
        &self,
        filters: Vec<Filter>,
        opts: Option<SubscribeAutoCloseOptions>,
    ) -> SubscriptionId {
        self.subscribe(filters, opts).await
    }

    async fn get_events_of(
        &self,
        filters: Vec<Filter>,
        timeout: Option<Duration>,
    ) -> Result<Vec<Event>, Error> {
        self.get_events_of(filters, timeout).await
    }

    async fn set_signer(&self, signer: Option<NostrSigner>) {
        self.set_signer(signer).await
    }
}
