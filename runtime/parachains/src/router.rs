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
use sp_std::collections::vec_deque::VecDeque;
use frame_support::{decl_error, decl_module, decl_storage, weights::Weight, traits::Get};
use sp_runtime::traits::{BlakeTwo256, Hash as HashT, SaturatedConversion};
use primitives::v1::{Id as ParaId, DownwardMessage, InboundDownwardMessage, Hash, UpwardMessage};
use codec::Encode;

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
		// no-op for now, will be filled in the following commits
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
}
