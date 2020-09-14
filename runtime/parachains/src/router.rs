// Copyright 2020 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! The router module is responsible for handling messaging.
//!
//! The core of the messaging is checking and processing messages sent out by the candidates,
//! routing the messages at their destinations and informing the parachains about the incoming
//! messages.

use crate::{
	configuration::{self, HostConfiguration},
	initializer,
};
use sp_std::prelude::*;
use sp_std::collections::{btree_map::BTreeMap, vec_deque::VecDeque};
use frame_support::{decl_error, decl_module, decl_storage, weights::Weight, traits::Get};
use sp_runtime::traits::{BlakeTwo256, Hash as HashT, SaturatedConversion};
use primitives::v1::{
	Balance, DownwardMessage, Hash, HrmpChannelId, Id as ParaId, InboundDownwardMessage,
	InboundHrmpMessage, UpwardMessage, SessionIndex,
};
use codec::{Encode, Decode};

/// A description of a request to open an HRMP channel.
#[derive(Encode, Decode)]
struct HrmpOpenChannelRequest {
	/// Indicates if this request was confirmed by the recipient.
	confirmed: bool,
	/// How many session boundaries ago this request was seen.
	age: SessionIndex,
	/// The amount that the sender supplied at the time of creation of this request.
	sender_deposit: Balance,
	/// The maximum number of messages that can be pending in the channel at once.
	limit_used_places: u32,
	/// The maximum total size of the messages that can be pending in the channel at once.
	limit_used_bytes: u32,
}

/// A metadata of an HRMP channel.
#[derive(Encode, Decode)]
struct HrmpChannel {
	/// The amount that the sender supplied as a deposit when opening this channel.
	sender_deposit: Balance,
	/// The amount that the recipient supplied as a deposit when accepting opening this channel.
	recipient_deposit: Balance,
	/// The maximum number of messages that can be pending in the channel at once.
	limit_used_places: u32,
	/// The maximum total size of the messages that can be pending in the channel at once.
	limit_used_bytes: u32,
	/// The maximum message size that could be put into the channel.
	limit_message_size: u32,
	/// The current number of messages pending in the channel.
	/// Invariant: should be less or equal to `limit_used_places`.
	used_places: u32,
	/// The total size in bytes of all message payloads in the channel.
	/// Invariant: should be less or equal to `limit_used_bytes`.
	used_bytes: u32,
	/// A head of the Message Queue Chain for this channel. Each link in this chain has a form:
	/// `(prev_head, B, H(M))`, where
	/// - `prev_head`: is the previous value of `mqc_head` or zero if none.
	/// - `B`: is the [relay-chain] block number in which a message was appended
	/// - `H(M)`: is the hash of the message being appended.
	/// This value is initialized to a special value that consists of all zeroes which indicates
	/// that no messages were previously added.
	mqc_head: Option<Hash>,
}

pub trait Trait: frame_system::Trait + configuration::Trait {}

decl_storage! {
	trait Store for Module<T: Trait> as Router {
		/// Paras that are to be cleaned up at the end of the session.
		/// The entries are sorted ascending by the para id.
		OutgoingParas: Vec<ParaId>;

		/*
		 * Downward Message Passing (DMP)
		 *
		 * Storage layout required for implementation of DMP.
		 */

		/// The downward messages addressed for a certain para.
		DownwardMessageQueues: map hasher(twox_64_concat) ParaId => Vec<InboundDownwardMessage<T::BlockNumber>>;
		/// A mapping that stores the downward message queue MQC head for each para.
		///
		/// Each link in this chain has a form:
		/// `(prev_head, B, H(M))`, where
		/// - `prev_head`: is the previous head hash or zero if none.
		/// - `B`: is the relay-chain block number in which a message was appended.
		/// - `H(M)`: is the hash of the message being appended.
		DownwardMessageQueueHeads: map hasher(twox_64_concat) ParaId => Option<Hash>;

		/*
		 * Upward Message Passing (UMP)
		 *
		 * Storage layout required for UMP, specifically dispatchable upward messages.
		 */

		/// Dispatchable objects ready to be dispatched onto the relay chain. The messages are processed in FIFO order.
		RelayDispatchQueues: map hasher(twox_64_concat) ParaId => VecDeque<UpwardMessage>;
		/// Size of the dispatch queues. Caches sizes of the queues in `RelayDispatchQueue`.
		/// First item in the tuple is the count of messages and second
		/// is the total length (in bytes) of the message payloads.
		RelayDispatchQueueSize: map hasher(twox_64_concat) ParaId => (u32, u32);
		/// The ordered list of `ParaId`s that have a `RelayDispatchQueue` entry.
		NeedsDispatch: Vec<ParaId>;
		/// This is the para that gets will get dispatched first during the next upward dispatchable queue
		/// execution round.
		NextDispatchRoundStartWith: Option<ParaId>;

		/*
		 * Horizontally Relay-routed Message Passing (HRMP)
		 *
		 * HRMP related storage layout
		 */

		/// The set of pending HRMP open channel requests.
		///
		/// The set is accompanied by a list for iteration.
		///
		/// Invariant:
		/// - There are no channels that exists in list but not in the set and vice versa.
		HrmpOpenChannelRequests: map hasher(twox_64_concat) HrmpChannelId => Option<HrmpOpenChannelRequest>;
		HrmpOpenChannelRequestsList: Vec<HrmpChannelId>;

		/// This mapping tracks how many open channel requests are inititated by a given sender para.
		/// Invariant: `HrmpOpenChannelRequests` should contain the same number of items that has `(X, _)`
		/// as the number of `HrmpOpenChannelRequestCount` for `X`.
		HrmpOpenChannelRequestCount: map hasher(twox_64_concat) ParaId => u32;
		/// This mapping tracks how many open channel requests were accepted by a given recipient para.
		/// Invariant: `HrmpOpenChannelRequests` should contain the same number of items `(_, X)` with
		/// `confirmed` set to true, as the number of `HrmpAcceptedChannelRequestCount` for `X`.
		HrmpAcceptedChannelRequestCount: map hasher(twox_64_concat) ParaId => u32;

		/// A set of pending HRMP close channel requests that are going to be closed during the session change.
		/// Used for checking if a given channel is registered for closure.
		///
		/// The set is accompanied by a list for iteration.
		///
		/// Invariant:
		/// - There are no channels that exists in list but not in the set and vice versa.
		HrmpCloseChannelRequests: map hasher(twox_64_concat) HrmpChannelId => Option<()>;
		HrmpCloseChannelRequestsList: Vec<HrmpChannelId>;

		/// The HRMP watermark associated with each para.
		HrmpWatermarks: map hasher(twox_64_concat) ParaId => Option<T::BlockNumber>;
		/// HRMP channel data associated with each para.
		HrmpChannels: map hasher(twox_64_concat) HrmpChannelId => Option<HrmpChannel>;
		/// The indexes that map all senders to their recievers and vise versa.
		/// Invariants:
		/// - for each ingress index entry for `P` each item `I` in the index should present in `HrmpChannels` as `(I, P)`.
		/// - for each egress index entry for `P` each item `E` in the index should present in `HrmpChannels` as `(P, E)`.
		/// - there should be no other dangling channels in `HrmpChannels`.
		HrmpIngressChannelsIndex: map hasher(twox_64_concat) ParaId => Vec<ParaId>;
		HrmpEgressChannelsIndex: map hasher(twox_64_concat) ParaId => Vec<ParaId>;
		/// Storage for the messages for each channel.
		/// Invariant: cannot be non-empty if the corresponding channel in `HrmpChannels` is `None`.
		HrmpChannelContents: map hasher(twox_64_concat) HrmpChannelId => Vec<InboundHrmpMessage<T::BlockNumber>>;
		/// Maintains a mapping that can be used to answer the question:
		/// What paras sent a message at the given block number for a given reciever.
		/// Invariant: The para ids vector is never empty.
		HrmpChannelDigests: map hasher(twox_64_concat) ParaId => Vec<(T::BlockNumber, Vec<ParaId>)>;
	}
}

decl_error! {
	pub enum Error for Module<T: Trait> { }
}

decl_module! {
	/// The router module.
	pub struct Module<T: Trait> for enum Call where origin: <T as frame_system::Trait>::Origin {
		type Error = Error<T>;
	}
}

impl<T: Trait> Module<T> {
	/// Block initialization logic, called by initializer.
	pub(crate) fn initializer_initialize(_now: T::BlockNumber) -> Weight {
		0
	}

	/// Block finalization logic, called by initializer.
	pub(crate) fn initializer_finalize() {}

	/// Called by the initializer to note that a new session has started.
	pub(crate) fn initializer_on_new_session(
		_notification: &initializer::SessionChangeNotification<T::BlockNumber>,
	) {
		let outgoing = OutgoingParas::take();
		for outgoing_para in outgoing {
			// DMP
			<Self as Store>::DownwardMessageQueues::remove(&outgoing_para);
			<Self as Store>::DownwardMessageQueueHeads::remove(&outgoing_para);

			// UMP
			<Self as Store>::RelayDispatchQueueSize::remove(&outgoing_para);
			<Self as Store>::RelayDispatchQueues::remove(&outgoing_para);
			<Self as Store>::NeedsDispatch::mutate(|v| {
				if let Ok(i) = v.binary_search(&outgoing_para) {
					v.remove(i);
				}
			});
			<Self as Store>::NextDispatchRoundStartWith::mutate(|v| {
				*v = v.filter(|p| *p == outgoing_para)
			})
		}
	}

	/// Schedule a para to be cleaned up at the start of the next session.
	pub fn schedule_para_cleanup(id: ParaId) {
		OutgoingParas::mutate(|v| {
			if let Err(i) = v.binary_search(&id) {
				v.insert(i, id);
			}
		});
	}

	/// Enqueue a downward message to a specific recipient para.
	///
	/// When encoded, the message should not exceed the `config.critical_downward_message_size`.
	/// Otherwise, the message won't be sent and `Err` will be returned.
	pub fn queue_downward_message(
		config: &HostConfiguration<T::BlockNumber>,
		para: ParaId,
		msg: DownwardMessage,
	) -> Result<(), ()> {
		let serialized_len = msg.encode().len() as u32;
		if serialized_len > config.critical_downward_message_size {
			return Err(());
		}

		let inbound = InboundDownwardMessage {
			msg,
			sent_at: <frame_system::Module<T>>::block_number(),
		};

		// obtain the new link in the MQC and update the head.
		<Self as Store>::DownwardMessageQueueHeads::mutate(para, |head| {
			let prev_head = head.unwrap_or(Default::default());
			let new_head = BlakeTwo256::hash_of(&(
				prev_head,
				inbound.sent_at,
				T::Hashing::hash_of(&inbound.msg),
			));
			*head = Some(new_head);
		});

		<Self as Store>::DownwardMessageQueues::mutate(para, |v| {
			v.push(inbound);
		});

		Ok(())
	}

	/// Checks if the number of processed downward messages is valid, i.e.:
	///
	/// - if there are pending messages then `processed_downward_messages` should be at least 1,
	/// - `processed_downward_messages` should not be greater than the number of pending messages.
	///
	/// Returns true if all checks have been passed.
	pub(crate) fn check_processed_downward_messages(
		para: ParaId,
		processed_downward_messages: u32,
	) -> bool {
		let dmq_length = Self::dmq_length(para);

		if dmq_length > 0 && processed_downward_messages == 0 {
			return false;
		}
		if dmq_length < processed_downward_messages {
			return false;
		}

		true
	}

	/// Check that all the upward messages sent by a candidate pass the acceptance criteria. Returns
	/// false, if any of the messages doesn't pass.
	pub(crate) fn check_upward_messages(
		config: &HostConfiguration<T::BlockNumber>,
		para: ParaId,
		upward_messages: &[UpwardMessage],
	) -> bool {
		if upward_messages.len() as u32 > config.max_upward_message_num_per_candidate {
			return false;
		}

		let (mut para_queue_count, mut para_queue_size) =
			<Self as Store>::RelayDispatchQueueSize::get(&para);

		for msg in upward_messages {
			para_queue_count += 1;
			para_queue_size += msg.len() as u32;
		}

		// make sure that the queue is not overfilled.
		// we do it here only once since returning false invalidates the whole relay-chain block.
		if para_queue_count > config.max_upward_queue_count
			|| para_queue_size > config.max_upward_queue_size
		{
			return false;
		}

		true
	}

	/// Enacts all the upward messages sent by a candidate.
	pub(crate) fn enact_upward_messages(para: ParaId, upward_messages: &[UpwardMessage]) -> Weight {
		let mut weight = 0;

		if !upward_messages.is_empty() {
			let (extra_cnt, extra_size) = upward_messages
				.iter()
				.fold((0, 0), |(cnt, size), d| (cnt + 1, size + d.len() as u32));

			<Self as Store>::RelayDispatchQueues::mutate(&para, |v| {
				v.extend(upward_messages.iter().cloned())
			});

			<Self as Store>::RelayDispatchQueueSize::mutate(
				&para,
				|(ref mut cnt, ref mut size)| {
					*cnt += extra_cnt;
					*size += extra_size;
				},
			);

			<Self as Store>::NeedsDispatch::mutate(|v| {
				if let Err(i) = v.binary_search(&para) {
					v.insert(i, para);
				}
			});

			weight += T::DbWeight::get().reads_writes(3, 3);
		}

		weight
	}

	/// Prunes the specified number of messages from the downward message queue of the given para.
	pub(crate) fn prune_dmq(para: ParaId, processed_downward_messages: u32) -> Weight {
		<Self as Store>::DownwardMessageQueues::mutate(para, |q| {
			let processed_downward_messages = processed_downward_messages as usize;
			if processed_downward_messages > q.len() {
				// reaching this branch is unexpected due to the constraint established by
				// `check_processed_downward_messages`. But better be safe than sorry.
				q.clear();
			} else {
				*q = q.split_off(processed_downward_messages);
			}
		});
		T::DbWeight::get().reads_writes(1, 1)
	}

	/// Returns the Head of Message Queue Chain for the given para or `None` if there is none
	/// associated with it.
	pub(crate) fn dmq_mqc_head(para: ParaId) -> Option<Hash> {
		<Self as Store>::DownwardMessageQueueHeads::get(&para)
	}

	/// Returns the number of pending downward messages addressed to the given para.
	///
	/// Returns 0 if the para doesn't have an associated downward message queue.
	pub(crate) fn dmq_length(para: ParaId) -> u32 {
		<Self as Store>::DownwardMessageQueues::decode_len(&para)
			.unwrap_or(0)
			.saturated_into::<u32>()
	}

	/// Devote some time into dispatching pending upward messages.
	pub(crate) fn process_pending_upward_messages() {
		let mut weight = 0;

		let mut queue_cache: BTreeMap<ParaId, VecDeque<UpwardMessage>> = BTreeMap::new();

		let mut needs_dispatch: Vec<ParaId> = <Self as Store>::NeedsDispatch::get();
		let start_with = <Self as Store>::NextDispatchRoundStartWith::get();

		let config = <configuration::Module<T>>::config();

		let mut idx = match start_with {
			Some(para) => match needs_dispatch.binary_search(&para) {
				Ok(found_idx) => found_idx,
				// well, that's weird, since the `NextDispatchRoundStartWith` is supposed to be reset.
				// let's select 0 as the starting index as a safe bet.
				Err(_supposed_idx) => 0,
			},
			None => 0,
		};

		loop {
			// find the next dispatchee
			let dispatchee = match needs_dispatch.get(idx) {
				Some(para) => {
					// update the index now. It may be used to set `NextDispatchRoundStartWith`.
					idx = (idx + 1) % needs_dispatch.len();
					*para
				}
				None => {
					// no pending upward queues need processing at the moment.
					break;
				}
			};

			if weight >= config.preferred_dispatchable_upward_messages_step_weight {
				// Then check whether we've reached or overshoot the
				// preferred weight for the dispatching stage.
				//
				// if so - bail.
				break;
			}

			// deuque the next message from the queue of the dispatchee
			let queue = queue_cache
				.entry(dispatchee)
				.or_insert_with(|| <Self as Store>::RelayDispatchQueues::get(&dispatchee));
			match queue.pop_front() {
				Some(upward_msg) => {
					// process the upward message
					match self::xcm::Xcm::decode(&mut &upward_msg[..]) {
						Ok(xcm) => {
							if self::xcm::estimate_weight(&xcm)
								<= config.dispatchable_upward_message_critical_weight
							{
								weight += match self::xcm::execute(xcm) {
									Ok(w) => w,
									Err(w) => w,
								};
							}
						}
						Err(_) => {}
					}
				}
				None => {}
			}

			if queue.is_empty() {
				// the queue is empty - this para doesn't need attention anymore.
				match needs_dispatch.binary_search(&dispatchee) {
					Ok(i) => {
						let _ = needs_dispatch.remove(i);
					}
					Err(_) => {
						// the invariant is we dispatch only queues that present in the
						// `needs_dispatch` in the first place.
						//
						// that should not be harmful though.
						debug_assert!(false);
					}
				}
			}
		}

		let next_one = needs_dispatch.get(idx).cloned();
		<Self as Store>::NextDispatchRoundStartWith::set(next_one);
		<Self as Store>::NeedsDispatch::put(needs_dispatch);
	}
}

mod xcm {
	//! A plug for the time being until we have XCM merged.
	use frame_support::weights::Weight;
	use codec::{Encode, Decode};

	#[derive(Clone, Eq, PartialEq, Encode, Decode)]
	pub enum Xcm {}

	// we expect the following functions to be satisfied by an implementation of the XcmExecute
	// trait.

	pub fn execute(xcm: Xcm) -> Result<Weight, Weight> {
		match xcm {}
	}

	pub fn estimate_weight(xcm: &Xcm) -> Weight {
		match *xcm {}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use primitives::v1::BlockNumber;
	use frame_support::traits::{OnFinalize, OnInitialize};

	use crate::mock::{Configuration, System, Router, new_test_ext, GenesisConfig as MockGenesisConfig};

	fn run_to_block(to: BlockNumber, new_session: Option<Vec<BlockNumber>>) {
		while System::block_number() < to {
			let b = System::block_number();
			Router::initializer_finalize();
			System::on_finalize(b);

			System::on_initialize(b + 1);
			System::set_block_number(b + 1);

			if new_session.as_ref().map_or(false, |v| v.contains(&(b + 1))) {
				Router::initializer_on_new_session(&Default::default());
			}
			Router::initializer_initialize(b + 1);
		}
	}

	fn default_genesis_config() -> MockGenesisConfig {
		MockGenesisConfig {
			configuration: crate::configuration::GenesisConfig {
				config: crate::configuration::HostConfiguration {
					critical_downward_message_size: 1024,
					..Default::default()
				},
			},
			..Default::default()
		}
	}

	fn queue_downward_message(para_id: ParaId, msg: DownwardMessage) -> Result<(), ()> {
		Router::queue_downward_message(&Configuration::config(), para_id, msg)
	}

	#[test]
	fn scheduled_cleanup_performed() {
		let a = ParaId::from(1312);
		let b = ParaId::from(228);
		let c = ParaId::from(123);

		new_test_ext(default_genesis_config()).execute_with(|| {
			run_to_block(1, None);

			// enqueue downward messages to A, B and C.
			queue_downward_message(a, vec![1, 2, 3]).unwrap();
			queue_downward_message(b, vec![4, 5, 6]).unwrap();
			queue_downward_message(c, vec![7, 8, 9]).unwrap();

			Router::schedule_para_cleanup(a);

			// run to block without session change.
			run_to_block(2, None);

			assert!(!<Router as Store>::DownwardMessageQueues::get(&a).is_empty());
			assert!(!<Router as Store>::DownwardMessageQueues::get(&b).is_empty());
			assert!(!<Router as Store>::DownwardMessageQueues::get(&c).is_empty());

			Router::schedule_para_cleanup(b);

			// run to block changing the session.
			run_to_block(3, Some(vec![3]));

			assert!(<Router as Store>::DownwardMessageQueues::get(&a).is_empty());
			assert!(<Router as Store>::DownwardMessageQueues::get(&b).is_empty());
			assert!(!<Router as Store>::DownwardMessageQueues::get(&c).is_empty());

			// verify that the outgoing paras are emptied.
			assert!(OutgoingParas::get().is_empty())
		});
	}

	#[test]
	fn dmq_length_and_head_updated_properly() {
		let a = ParaId::from(1312);
		let b = ParaId::from(228);

		new_test_ext(default_genesis_config()).execute_with(|| {
			assert_eq!(Router::dmq_length(a), 0);
			assert_eq!(Router::dmq_length(b), 0);

			queue_downward_message(a, vec![1, 2, 3]).unwrap();

			assert_eq!(Router::dmq_length(a), 1);
			assert_eq!(Router::dmq_length(b), 0);
			assert!(Router::dmq_mqc_head(a).is_some());
			assert!(Router::dmq_mqc_head(b).is_none());
		});
	}

	#[test]
	fn check_processed_downward_messages() {
		let a = ParaId::from(1312);

		new_test_ext(default_genesis_config()).execute_with(|| {
			// processed_downward_messages=0 is allowed when the DMQ is empty.
			assert!(Router::check_processed_downward_messages(a, 0));

			queue_downward_message(a, vec![1, 2, 3]).unwrap();
			queue_downward_message(a, vec![4, 5, 6]).unwrap();
			queue_downward_message(a, vec![7, 8, 9]).unwrap();

			// 0 doesn't pass if the DMQ has msgs.
			assert!(!Router::check_processed_downward_messages(a, 0));
			// a candidate can consume up to 3 messages
			assert!(Router::check_processed_downward_messages(a, 1));
			assert!(Router::check_processed_downward_messages(a, 2));
			assert!(Router::check_processed_downward_messages(a, 3));
			// there is no 4 messages in the queue
			assert!(!Router::check_processed_downward_messages(a, 4));
		});
	}

	#[test]
	fn dmq_pruning() {
		let a = ParaId::from(1312);

		new_test_ext(default_genesis_config()).execute_with(|| {
			assert_eq!(Router::dmq_length(a), 0);

			queue_downward_message(a, vec![1, 2, 3]).unwrap();
			queue_downward_message(a, vec![4, 5, 6]).unwrap();
			queue_downward_message(a, vec![7, 8, 9]).unwrap();
			assert_eq!(Router::dmq_length(a), 3);

			// pruning 0 elements shouldn't change anything.
			Router::prune_dmq(a, 0);
			assert_eq!(Router::dmq_length(a), 3);

			Router::prune_dmq(a, 2);
			assert_eq!(Router::dmq_length(a), 1);
		});
	}

	#[test]
	fn queue_downward_message_critical() {
		let a = ParaId::from(1312);

		let mut genesis = default_genesis_config();
		genesis.configuration.config.critical_downward_message_size = 7;

		new_test_ext(genesis).execute_with(|| {
			let smol = [0; 3].to_vec();
			let big = [0; 8].to_vec();

			// still within limits
			assert_eq!(smol.encode().len(), 4);
			assert!(queue_downward_message(a, smol).is_ok());

			// that's too big
			assert_eq!(big.encode().len(), 9);
			assert!(queue_downward_message(a, big).is_err());
		});
	}

	#[test]
	fn ump_dispatch_empty() {
		new_test_ext(default_genesis_config()).execute_with(|| {
			// make sure that the case with empty queues is handled properly
			Router::process_pending_upward_messages();
		});
	}
}
