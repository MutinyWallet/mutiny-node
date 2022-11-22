#![allow(clippy::all)]
use lightning_invoice::{CreationError, Currency, Invoice, InvoiceBuilder, SignOrCreationError};

use bitcoin::bech32::ToBase32;
use bitcoin_hashes::Hash;
use core::ops::Deref;
use core::time::Duration;
use instant::SystemTime;
use lightning::chain::keysinterface::{KeysInterface, Recipient, Sign};
use lightning::ln::channelmanager::{ChannelDetails, MIN_FINAL_CLTV_EXPIRY};
use lightning::ln::channelmanager::{PhantomRouteHints, MIN_CLTV_EXPIRY_DELTA};
use lightning::ln::inbound_payment::{create, create_from_hash, ExpandedKey};
use lightning::ln::PaymentHash;
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop};
use secp256k1::PublicKey;
use std::collections::{hash_map, HashMap};

pub fn create_phantom_invoice<Signer: Sign, K: Deref>(
    amt_msat: Option<u64>,
    payment_hash: Option<PaymentHash>,
    description: String,
    invoice_expiry_delta_secs: u32,
    phantom_route_hints: Vec<PhantomRouteHints>,
    keys_manager: K,
    network: Currency,
) -> Result<Invoice, SignOrCreationError<()>>
where
    K::Target: KeysInterface,
{
    _create_phantom_invoice::<Signer, K>(
        amt_msat,
        payment_hash,
        description,
        invoice_expiry_delta_secs,
        phantom_route_hints,
        keys_manager,
        network,
    )
}

fn _create_phantom_invoice<Signer: Sign, K: Deref>(
    amt_msat: Option<u64>,
    payment_hash: Option<PaymentHash>,
    description: String,
    invoice_expiry_delta_secs: u32,
    phantom_route_hints: Vec<PhantomRouteHints>,
    keys_manager: K,
    network: Currency,
) -> Result<Invoice, SignOrCreationError<()>>
where
    K::Target: KeysInterface,
{
    if phantom_route_hints.len() == 0 {
        return Err(SignOrCreationError::CreationError(
            CreationError::MissingRouteHints,
        ));
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let invoice = InvoiceBuilder::new(network).description(description);

    // If we ever see performance here being too slow then we should probably take this ExpandedKey as a parameter instead.
    let keys = ExpandedKey::new(&keys_manager.get_inbound_payment_key_material());
    let (payment_hash, payment_secret) = if let Some(payment_hash) = payment_hash {
        let payment_secret = create_from_hash(
            &keys,
            amt_msat,
            payment_hash,
            invoice_expiry_delta_secs,
            now,
        )
        .map_err(|_| SignOrCreationError::CreationError(CreationError::InvalidAmount))?;
        (payment_hash, payment_secret)
    } else {
        create(
            &keys,
            amt_msat,
            invoice_expiry_delta_secs,
            &keys_manager,
            now,
        )
        .map_err(|_| SignOrCreationError::CreationError(CreationError::InvalidAmount))?
    };

    let mut invoice = invoice
        .duration_since_epoch(Duration::from_secs(now))
        .payment_hash(Hash::from_slice(&payment_hash.0).unwrap())
        .payment_secret(payment_secret)
        .min_final_cltv_expiry(MIN_FINAL_CLTV_EXPIRY.into())
        .expiry_time(Duration::from_secs(invoice_expiry_delta_secs.into()));
    if let Some(amt) = amt_msat {
        invoice = invoice.amount_milli_satoshis(amt);
    }

    for PhantomRouteHints {
        channels,
        phantom_scid,
        real_node_pubkey,
    } in phantom_route_hints
    {
        let mut route_hints = filter_channels(channels, amt_msat);

        // If we have any public channel, the route hints from `filter_channels` will be empty.
        // In that case we create a RouteHint on which we will push a single hop with the phantom
        // route into the invoice, and let the sender find the path to the `real_node_pubkey`
        // node by looking at our public channels.
        if route_hints.is_empty() {
            route_hints.push(RouteHint(vec![]))
        }
        for mut route_hint in route_hints {
            route_hint.0.push(RouteHintHop {
                src_node_id: real_node_pubkey,
                short_channel_id: phantom_scid,
                fees: RoutingFees {
                    base_msat: 0,
                    proportional_millionths: 0,
                },
                cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA,
                htlc_minimum_msat: None,
                htlc_maximum_msat: None,
            });
            invoice = invoice.private_route(route_hint.clone());
        }
    }

    let raw_invoice = match invoice.build_raw() {
        Ok(inv) => inv,
        Err(e) => return Err(SignOrCreationError::CreationError(e)),
    };
    let hrp_str = raw_invoice.hrp.to_string();
    let hrp_bytes = hrp_str.as_bytes();
    let data_without_signature = raw_invoice.data.to_base32();
    let signed_raw_invoice = raw_invoice.sign(|_| {
        keys_manager.sign_invoice(hrp_bytes, &data_without_signature, Recipient::PhantomNode)
    });
    match signed_raw_invoice {
        Ok(inv) => Ok(Invoice::from_signed(inv).unwrap()),
        Err(e) => Err(SignOrCreationError::SignError(e)),
    }
}

fn filter_channels(
    channels: Vec<ChannelDetails>,
    min_inbound_capacity_msat: Option<u64>,
) -> Vec<RouteHint> {
    let mut filtered_channels: HashMap<PublicKey, ChannelDetails> = HashMap::new();
    let min_inbound_capacity = min_inbound_capacity_msat.unwrap_or(0);
    let mut min_capacity_channel_exists = false;
    let mut online_channel_exists = false;
    let mut online_min_capacity_channel_exists = false;

    for channel in channels.into_iter().filter(|chan| chan.is_channel_ready) {
        if channel.get_inbound_payment_scid().is_none()
            || channel.counterparty.forwarding_info.is_none()
        {
            continue;
        }

        if channel.is_public {
            // If any public channel exists, return no hints and let the sender
            // look at the public channels instead.
            return vec![];
        }

        if channel.inbound_capacity_msat >= min_inbound_capacity {
            if !min_capacity_channel_exists {
                min_capacity_channel_exists = true;
            }

            if channel.is_usable {
                online_min_capacity_channel_exists = true;
            }
        }

        if channel.is_usable {
            if !online_channel_exists {
                online_channel_exists = true;
            }
        }

        match filtered_channels.entry(channel.counterparty.node_id) {
            hash_map::Entry::Occupied(mut entry) => {
                let current_max_capacity = entry.get().inbound_capacity_msat;
                if channel.inbound_capacity_msat < current_max_capacity {
                    continue;
                }
                entry.insert(channel);
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(channel);
            }
        }
    }

    let route_hint_from_channel = |channel: ChannelDetails| {
        let forwarding_info = channel.counterparty.forwarding_info.as_ref().unwrap();
        RouteHint(vec![RouteHintHop {
            src_node_id: channel.counterparty.node_id,
            short_channel_id: channel.get_inbound_payment_scid().unwrap(),
            fees: RoutingFees {
                base_msat: forwarding_info.fee_base_msat,
                proportional_millionths: forwarding_info.fee_proportional_millionths,
            },
            cltv_expiry_delta: forwarding_info.cltv_expiry_delta,
            htlc_minimum_msat: channel.inbound_htlc_minimum_msat,
            htlc_maximum_msat: channel.inbound_htlc_maximum_msat,
        }])
    };
    // If all channels are private, prefer to return route hints which have a higher capacity than
    // the payment value and where we're currently connected to the channel counterparty.
    // Even if we cannot satisfy both goals, always ensure we include *some* hints, preferring
    // those which meet at least one criteria.
    filtered_channels
        .into_iter()
        .map(|(_, channel)| channel)
        .filter(|channel| {
            let has_enough_capacity = channel.inbound_capacity_msat >= min_inbound_capacity;
            let include_channel = if online_min_capacity_channel_exists {
                has_enough_capacity && channel.is_usable
            } else if min_capacity_channel_exists && online_channel_exists {
                // If there are some online channels and some min_capacity channels, but no
                // online-and-min_capacity channels, just include the min capacity ones and ignore
                // online-ness.
                has_enough_capacity
            } else if min_capacity_channel_exists {
                has_enough_capacity
            } else if online_channel_exists {
                channel.is_usable
            } else {
                true
            };

            if include_channel {
            } else if !has_enough_capacity {
            } else {
                debug_assert!(!channel.is_usable);
            }

            include_channel
        })
        .map(route_hint_from_channel)
        .collect::<Vec<RouteHint>>()
}
