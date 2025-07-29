use std::mem;

use alloy_consensus::{Block, BlockBody, EMPTY_OMMER_ROOT_HASH, Header, Sealed};
use alloy_eips::{
    BlockNumHash, calc_next_block_base_fee, eip1898::BlockWithParent, eip7840::BlobParams,
};
use alloy_primitives::{
    Address, B64, B256, BlockNumber, Bloom, Bytes, FixedBytes, Sealable, U256, keccak256,
};
use alloy_rlp::{BufMut, Decodable, Encodable, length_of_length};
use alloy_trie::EMPTY_ROOT_HASH;
use reth_chainspec::BaseFeeParams;
use reth_codecs::Compact;
use reth_primitives_traits::{BlockHeader, InMemorySize};
use reth_tracing::tracing::debug;
use serde::{Deserialize, Serialize};

/// The header type of this node
///
/// This type extends the regular ethereum header with an extension.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    // derive_more::AsRef,
    // derive_more::Deref,
    // derive_more::DerefMut,
    Default,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct GnosisHeader {
    /// The Keccak 256-bit hash of the parent
    /// block’s header, in its entirety; formally Hp.
    pub parent_hash: B256,
    /// The Keccak 256-bit hash of the ommers list portion of this block; formally Ho.
    #[cfg_attr(feature = "serde", serde(rename = "sha3Uncles", alias = "ommersHash"))]
    pub ommers_hash: B256,
    /// The 160-bit address to which all fees collected from the successful mining of this block
    /// be transferred; formally Hc.
    #[cfg_attr(feature = "serde", serde(rename = "miner", alias = "beneficiary"))]
    pub beneficiary: Address,
    /// The Keccak 256-bit hash of the root node of the state trie, after all transactions are
    /// executed and finalisations applied; formally Hr.
    pub state_root: B256,
    /// The Keccak 256-bit hash of the root node of the trie structure populated with each
    /// transaction in the transactions list portion of the block; formally Ht.
    pub transactions_root: B256,
    /// The Keccak 256-bit hash of the root node of the trie structure populated with the receipts
    /// of each transaction in the transactions list portion of the block; formally He.
    pub receipts_root: B256,
    /// The Bloom filter composed from indexable information (logger address and log topics)
    /// contained in each log entry from the receipt of each transaction in the transactions list;
    /// formally Hb.
    pub logs_bloom: Bloom,
    /// A scalar value corresponding to the difficulty level of this block. This can be calculated
    /// from the previous block’s difficulty level and the timestamp; formally Hd.
    pub difficulty: U256,
    /// A scalar value equal to the number of ancestor blocks. The genesis block has a number of
    /// zero; formally Hi.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub number: BlockNumber,
    /// A scalar value equal to the current limit of gas expenditure per block; formally Hl.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub gas_limit: u64,
    /// A scalar value equal to the total gas used in transactions in this block; formally Hg.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub gas_used: u64,
    /// A scalar value equal to the reasonable output of Unix’s time() at this block’s inception;
    /// formally Hs.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub timestamp: u64,
    /// An arbitrary byte array containing data relevant to this block. This must be 32 bytes or
    /// fewer; formally Hx.
    pub extra_data: Bytes,
    /// A 256-bit hash which, combined with the
    /// nonce, proves that a sufficient amount of computation has been carried out on this block;
    /// formally Hm.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub mix_hash: Option<B256>,
    /// A 64-bit value which, combined with the mixhash, proves that a sufficient amount of
    /// computation has been carried out on this block; formally Hn.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub nonce: Option<B64>,
    /// Gnosis-specific fields for Aura Consensus
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub aura_step: Option<U256>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub aura_seal: Option<FixedBytes<65>>,
    /// A scalar representing EIP1559 base fee which can move up or down each block according
    /// to a formula which is a function of gas used in parent block and gas target
    /// (block gas limit divided by elasticity multiplier) of parent block.
    /// The algorithm results in the base fee per gas increasing when blocks are
    /// above the gas target, and decreasing when blocks are below the gas target. The base fee per
    /// gas is burned.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            with = "alloy_serde::quantity::opt",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub base_fee_per_gas: Option<u64>,
    /// The Keccak 256-bit hash of the withdrawals list portion of this block.
    /// <https://eips.ethereum.org/EIPS/eip-4895>
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub withdrawals_root: Option<B256>,
    /// The total amount of blob gas consumed by the transactions within the block, added in
    /// EIP-4844.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            with = "alloy_serde::quantity::opt",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub blob_gas_used: Option<u64>,
    /// A running total of blob gas consumed in excess of the target, prior to the block. Blocks
    /// with above-target blob gas consumption increase this value, blocks with below-target blob
    /// gas consumption decrease it (bounded at 0). This was added in EIP-4844.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            with = "alloy_serde::quantity::opt",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub excess_blob_gas: Option<u64>,
    /// The hash of the parent beacon block's root is included in execution blocks, as proposed by
    /// EIP-4788.
    ///
    /// This enables trust-minimized access to consensus state, supporting staking pools, bridges,
    /// and more.
    ///
    /// The beacon roots contract handles root storage, enhancing Ethereum's functionalities.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub parent_beacon_block_root: Option<B256>,
    /// The Keccak 256-bit hash of the an RLP encoded list with each
    /// [EIP-7685] request in the block body.
    ///
    /// [EIP-7685]: https://eips.ethereum.org/EIPS/eip-7685
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub requests_hash: Option<B256>,
}

/// Bincode-compatible [`Header`] serde implementation.
pub mod serde_bincode_compat {
    use std::borrow::Cow;

    use alloy_primitives::{Address, B64, B256, BlockNumber, Bloom, Bytes, FixedBytes, U256};
    use reth_primitives_traits::serde_bincode_compat::SerdeBincodeCompat;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    /// Bincode-compatible [`super::Header`] serde implementation.
    ///
    /// Intended to use with the [`serde_with::serde_as`] macro in the following way:
    /// ```rust
    /// use alloy_consensus::{serde_bincode_compat, Header};
    /// use serde::{Deserialize, Serialize};
    /// use serde_with::serde_as;
    ///
    /// #[serde_as]
    /// #[derive(Serialize, Deserialize)]
    /// struct Data {
    ///     #[serde_as(as = "serde_bincode_compat::Header")]
    ///     header: Header,
    /// }
    /// ```
    #[derive(Debug, Serialize, Deserialize)]
    pub struct GnosisHeader<'a> {
        parent_hash: B256,
        ommers_hash: B256,
        beneficiary: Address,
        state_root: B256,
        transactions_root: B256,
        receipts_root: B256,
        #[serde(default)]
        withdrawals_root: Option<B256>,
        logs_bloom: Bloom,
        difficulty: U256,
        number: BlockNumber,
        gas_limit: u64,
        gas_used: u64,
        timestamp: u64,
        #[serde(default)]
        mix_hash: Option<B256>,
        #[serde(default)]
        nonce: Option<B64>,
        #[serde(default)]
        aura_step: Option<U256>,
        #[serde(default)]
        aura_seal: Option<FixedBytes<65>>,
        #[serde(default)]
        base_fee_per_gas: Option<u64>,
        #[serde(default)]
        blob_gas_used: Option<u64>,
        #[serde(default)]
        excess_blob_gas: Option<u64>,
        #[serde(default)]
        parent_beacon_block_root: Option<B256>,
        #[serde(default)]
        requests_hash: Option<B256>,
        extra_data: Cow<'a, Bytes>,
    }

    impl<'a> From<&'a super::GnosisHeader> for GnosisHeader<'a> {
        fn from(value: &'a super::GnosisHeader) -> Self {
            Self {
                parent_hash: value.parent_hash,
                ommers_hash: value.ommers_hash,
                beneficiary: value.beneficiary,
                state_root: value.state_root,
                transactions_root: value.transactions_root,
                receipts_root: value.receipts_root,
                withdrawals_root: value.withdrawals_root,
                logs_bloom: value.logs_bloom,
                difficulty: value.difficulty,
                number: value.number,
                gas_limit: value.gas_limit,
                gas_used: value.gas_used,
                timestamp: value.timestamp,
                mix_hash: value.mix_hash,
                nonce: value.nonce,
                aura_step: value.aura_step,
                aura_seal: value.aura_seal,
                base_fee_per_gas: value.base_fee_per_gas,
                blob_gas_used: value.blob_gas_used,
                excess_blob_gas: value.excess_blob_gas,
                parent_beacon_block_root: value.parent_beacon_block_root,
                requests_hash: value.requests_hash,
                extra_data: Cow::Borrowed(&value.extra_data),
            }
        }
    }

    impl<'a> From<GnosisHeader<'a>> for super::GnosisHeader {
        fn from(value: GnosisHeader<'a>) -> Self {
            Self {
                parent_hash: value.parent_hash,
                ommers_hash: value.ommers_hash,
                beneficiary: value.beneficiary,
                state_root: value.state_root,
                transactions_root: value.transactions_root,
                receipts_root: value.receipts_root,
                withdrawals_root: value.withdrawals_root,
                logs_bloom: value.logs_bloom,
                difficulty: value.difficulty,
                number: value.number,
                gas_limit: value.gas_limit,
                gas_used: value.gas_used,
                timestamp: value.timestamp,
                mix_hash: value.mix_hash,
                nonce: value.nonce,
                aura_step: value.aura_step,
                aura_seal: value.aura_seal,
                base_fee_per_gas: value.base_fee_per_gas,
                blob_gas_used: value.blob_gas_used,
                excess_blob_gas: value.excess_blob_gas,
                parent_beacon_block_root: value.parent_beacon_block_root,
                requests_hash: value.requests_hash,
                extra_data: value.extra_data.into_owned(),
            }
        }
    }

    impl SerializeAs<super::GnosisHeader> for GnosisHeader<'_> {
        fn serialize_as<S>(source: &super::GnosisHeader, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            GnosisHeader::from(source).serialize(serializer)
        }
    }

    impl<'de> DeserializeAs<'de, super::GnosisHeader> for GnosisHeader<'de> {
        fn deserialize_as<D>(deserializer: D) -> Result<super::GnosisHeader, D::Error>
        where
            D: Deserializer<'de>,
        {
            GnosisHeader::deserialize(deserializer).map(Into::into)
        }
    }

    impl SerdeBincodeCompat for super::GnosisHeader {
        type BincodeRepr<'a> = GnosisHeader<'a>;

        fn as_repr(&self) -> Self::BincodeRepr<'_> {
            GnosisHeader::from(self)
        }

        fn from_repr(repr: Self::BincodeRepr<'_>) -> Self {
            repr.into()
        }
    }
}

impl GnosisHeader {
    /// Create a [`Block`] from the body and its header.
    pub fn into_block<T>(self, body: BlockBody<T>) -> Block<T> {
        body.into_block(self.into())
    }

    /// Heavy function that will calculate hash of data and will *not* save the change to metadata.
    ///
    /// Use [`Header::seal_slow`] and unlock if you need the hash to be persistent.
    pub fn hash_slow(&self) -> B256 {
        let mut out = Vec::<u8>::new();
        self.encode(&mut out);
        keccak256(&out)
    }

    /// Check if the ommers hash equals to empty hash list.
    pub fn ommers_hash_is_empty(&self) -> bool {
        self.ommers_hash == EMPTY_OMMER_ROOT_HASH
    }

    /// Check if the transaction root equals to empty root.
    pub fn transaction_root_is_empty(&self) -> bool {
        *self.transactions_root == *EMPTY_ROOT_HASH
    }

    /// Returns the blob fee for _this_ block according to the EIP-4844 spec.
    ///
    /// Returns `None` if `excess_blob_gas` is None
    pub fn blob_fee(&self, blob_params: BlobParams) -> Option<u128> {
        Some(blob_params.calc_blob_fee(self.excess_blob_gas?))
    }

    /// Returns the blob fee for the next block according to the EIP-4844 spec.
    ///
    /// Returns `None` if `excess_blob_gas` is None.
    ///
    /// See also [Self::next_block_excess_blob_gas]
    pub fn next_block_blob_fee(&self, blob_params: BlobParams) -> Option<u128> {
        Some(blob_params.calc_blob_fee(self.next_block_excess_blob_gas(blob_params)?))
    }

    /// Calculate base fee for next block according to the EIP-1559 spec.
    ///
    /// Returns a `None` if no base fee is set, no EIP-1559 support
    pub fn next_block_base_fee(&self, base_fee_params: BaseFeeParams) -> Option<u64> {
        Some(calc_next_block_base_fee(
            self.gas_used,
            self.gas_limit,
            self.base_fee_per_gas?,
            base_fee_params,
        ))
    }

    /// Calculate excess blob gas for the next block according to the EIP-4844
    /// spec.
    ///
    /// Returns a `None` if no excess blob gas is set, no EIP-4844 support
    pub fn next_block_excess_blob_gas(&self, blob_params: BlobParams) -> Option<u64> {
        Some(blob_params.next_block_excess_blob_gas(self.excess_blob_gas?, self.blob_gas_used?))
    }

    /// Calculate a heuristic for the in-memory size of the [Header].
    #[inline]
    pub fn size_of(&self) -> usize {
        mem::size_of::<B256>() + // parent hash
        mem::size_of::<B256>() + // ommers hash
        mem::size_of::<Address>() + // beneficiary
        mem::size_of::<B256>() + // state root
        mem::size_of::<B256>() + // transactions root
        mem::size_of::<B256>() + // receipts root
        mem::size_of::<Option<B256>>() + // withdrawals root
        mem::size_of::<Bloom>() + // logs bloom
        mem::size_of::<U256>() + // difficulty
        mem::size_of::<BlockNumber>() + // number
        mem::size_of::<u128>() + // gas limit
        mem::size_of::<u128>() + // gas used
        mem::size_of::<u64>() + // timestamp
        // mem::size_of::<B256>() + // mix hash
        // mem::size_of::<u64>() + // nonce
        mem::size_of::<Option<u128>>() + // base fee per gas
        mem::size_of::<Option<u128>>() + // blob gas used
        mem::size_of::<Option<u128>>() + // excess blob gas
        mem::size_of::<Option<B256>>() + // parent beacon block root
        mem::size_of::<Option<B256>>() + // requests root
        self.extra_data.len() // extra data
    }

    fn header_payload_length(&self) -> usize {
        let mut length = 0;
        length += self.parent_hash.length();
        length += self.ommers_hash.length();
        length += self.beneficiary.length();
        length += self.state_root.length();
        length += self.transactions_root.length();
        length += self.receipts_root.length();
        length += self.logs_bloom.length();
        length += self.difficulty.length();
        length += U256::from(self.number).length();
        length += U256::from(self.gas_limit).length();
        length += U256::from(self.gas_used).length();
        length += self.timestamp.length();
        length += self.extra_data.length();
        if self.is_post_merge() {
            // If the header is post-merge, we have mix_hash and nonce.
            length += self.mix_hash.as_ref().map_or(0, |hash| hash.length());
            length += self.nonce.as_ref().map_or(0, |nonce| nonce.length());
        } else {
            // If the header is pre-merge, we have aura_step and aura_seal.
            length += self.aura_step.unwrap_or(U256::ZERO).length();
            length += self.aura_seal.as_ref().map_or(0, |seal| seal.length());
        }
        // length += self.mix_hash.is_some().then(|| self.mix_hash.unwrap().length()).unwrap_or(0);
        // length += self.nonce.is_some().then(|| self.nonce.unwrap().length()).unwrap_or(0);
        // length += self.is_post_merge().then(|| self.aura_step.unwrap().length()).unwrap_or(0);
        // length += self.aura_seal.as_ref().map_or(0, |seal| seal.length());

        if let Some(base_fee) = self.base_fee_per_gas {
            // Adding base fee length if it exists.
            length += U256::from(base_fee).length();
        }

        if let Some(root) = self.withdrawals_root {
            // Adding withdrawals_root length if it exists.
            length += root.length();
        }

        if let Some(blob_gas_used) = self.blob_gas_used {
            // Adding blob_gas_used length if it exists.
            length += U256::from(blob_gas_used).length();
        }

        if let Some(excess_blob_gas) = self.excess_blob_gas {
            // Adding excess_blob_gas length if it exists.
            length += U256::from(excess_blob_gas).length();
        }

        if let Some(parent_beacon_block_root) = self.parent_beacon_block_root {
            length += parent_beacon_block_root.length();
        }

        if let Some(requests_hash) = self.requests_hash {
            length += requests_hash.length();
        }

        length
    }

    /// Returns the parent block's number and hash
    ///
    /// Note: for the genesis block the parent number is 0 and the parent hash is the zero hash.
    pub const fn parent_num_hash(&self) -> BlockNumHash {
        BlockNumHash {
            number: self.number.saturating_sub(1),
            hash: self.parent_hash,
        }
    }

    /// Returns the block's number and hash.
    ///
    /// Note: this hashes the header.
    pub fn num_hash_slow(&self) -> BlockNumHash {
        BlockNumHash {
            number: self.number,
            hash: self.hash_slow(),
        }
    }

    /// Returns the block's number and hash with the parent hash.
    ///
    /// Note: this hashes the header.
    pub fn num_hash_with_parent_slow(&self) -> BlockWithParent {
        BlockWithParent::new(self.parent_hash, self.num_hash_slow())
    }

    /// Seal the header with a known hash.
    ///
    /// WARNING: This method does not perform validation whether the hash is correct.
    #[inline]
    pub const fn seal(self, hash: B256) -> Sealed<Self> {
        Sealed::new_unchecked(self, hash)
    }

    /// True if the shanghai hardfork is active.
    ///
    /// This function checks that the withdrawals root field is present.
    pub const fn shanghai_active(&self) -> bool {
        self.withdrawals_root.is_some()
    }

    /// True if the Cancun hardfork is active.
    ///
    /// This function checks that the blob gas used field is present.
    pub const fn cancun_active(&self) -> bool {
        self.blob_gas_used.is_some()
    }

    /// True if the Prague hardfork is active.
    ///
    /// This function checks that the requests hash is present.
    pub const fn prague_active(&self) -> bool {
        self.requests_hash.is_some()
    }

    pub fn is_post_merge(&self) -> bool {
        self.mix_hash.is_some() && self.nonce.is_some()
    }

    pub fn to_alloy_header(&self) -> Header {
        if self.mix_hash.is_none() || self.nonce.is_none() {
            panic!(
                "GnosisHeader must have mix_hash and nonce set to convert to alloy_consensus::Header. All post-merge headers have these fields set."
            );
        }
        Header {
            parent_hash: self.parent_hash,
            ommers_hash: self.ommers_hash,
            beneficiary: self.beneficiary,
            state_root: self.state_root,
            transactions_root: self.transactions_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom,
            difficulty: self.difficulty,
            number: self.number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            mix_hash: self.mix_hash.unwrap(),
            nonce: self.nonce.unwrap(),
            base_fee_per_gas: self.base_fee_per_gas,
            withdrawals_root: self.withdrawals_root,
            blob_gas_used: self.blob_gas_used,
            excess_blob_gas: self.excess_blob_gas,
            parent_beacon_block_root: self.parent_beacon_block_root,
            requests_hash: self.requests_hash,
        }
    }
}

// derive from alloy_consensus::Header
impl From<Header> for GnosisHeader {
    fn from(inner: Header) -> Self {
        Self {
            parent_hash: inner.parent_hash,
            ommers_hash: inner.ommers_hash,
            beneficiary: inner.beneficiary,
            state_root: inner.state_root,
            transactions_root: inner.transactions_root,
            receipts_root: inner.receipts_root,
            logs_bloom: inner.logs_bloom,
            difficulty: inner.difficulty,
            number: inner.number,
            gas_limit: inner.gas_limit,
            gas_used: inner.gas_used,
            timestamp: inner.timestamp,
            extra_data: inner.extra_data,
            mix_hash: Some(inner.mix_hash),
            nonce: Some(inner.nonce),
            aura_seal: None,
            aura_step: None,
            base_fee_per_gas: None,         // Set later if needed
            withdrawals_root: None,         // Set later if needed
            blob_gas_used: None,            // Set later if needed
            excess_blob_gas: None,          // Set later if needed
            parent_beacon_block_root: None, // Set later if needed
            requests_hash: None,            // Set later if needed
        }
    }
}

impl From<GnosisHeader> for Header {
    fn from(gnosis_header: GnosisHeader) -> Self {
        if gnosis_header.mix_hash.is_none() || gnosis_header.nonce.is_none() {
            panic!(
                "GnosisHeader must have mix_hash and nonce set to convert to alloy_consensus::Header. All post-merge headers have these fields set."
            );
        }
        Header {
            parent_hash: gnosis_header.parent_hash,
            ommers_hash: gnosis_header.ommers_hash,
            beneficiary: gnosis_header.beneficiary,
            state_root: gnosis_header.state_root,
            transactions_root: gnosis_header.transactions_root,
            receipts_root: gnosis_header.receipts_root,
            logs_bloom: gnosis_header.logs_bloom,
            difficulty: gnosis_header.difficulty,
            number: gnosis_header.number,
            gas_limit: gnosis_header.gas_limit,
            gas_used: gnosis_header.gas_used,
            timestamp: gnosis_header.timestamp,
            extra_data: gnosis_header.extra_data,
            mix_hash: gnosis_header.mix_hash.unwrap(),
            nonce: gnosis_header.nonce.unwrap(),
            base_fee_per_gas: gnosis_header.base_fee_per_gas,
            withdrawals_root: gnosis_header.withdrawals_root,
            blob_gas_used: gnosis_header.blob_gas_used,
            excess_blob_gas: gnosis_header.excess_blob_gas,
            parent_beacon_block_root: gnosis_header.parent_beacon_block_root,
            requests_hash: gnosis_header.requests_hash,
        }
    }
}

// // impl Into<&alloy_consensus::Header> for GnosisHeader
// impl Into<&Header> for GnosisHeader {
//     fn into(self) -> &Header {
//         &self.to_alloy_header()
//     }
// }

impl AsRef<Self> for GnosisHeader {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Sealable for GnosisHeader {
    fn hash_slow(&self) -> B256 {
        let mut out = Vec::new();
        self.encode(&mut out);
        keccak256(&out)
    }
}

impl alloy_consensus::BlockHeader for GnosisHeader {
    fn parent_hash(&self) -> B256 {
        self.parent_hash
    }

    fn ommers_hash(&self) -> B256 {
        self.ommers_hash
    }

    fn beneficiary(&self) -> Address {
        self.beneficiary
    }

    fn state_root(&self) -> B256 {
        self.state_root
    }

    fn transactions_root(&self) -> B256 {
        self.transactions_root
    }

    fn receipts_root(&self) -> B256 {
        self.receipts_root
    }

    fn withdrawals_root(&self) -> Option<B256> {
        self.withdrawals_root
    }

    fn logs_bloom(&self) -> Bloom {
        self.logs_bloom
    }

    fn difficulty(&self) -> U256 {
        self.difficulty
    }

    fn number(&self) -> BlockNumber {
        self.number
    }

    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    fn gas_used(&self) -> u64 {
        self.gas_used
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }

    fn mix_hash(&self) -> Option<B256> {
        self.mix_hash
    }

    fn nonce(&self) -> Option<B64> {
        self.nonce
    }

    fn base_fee_per_gas(&self) -> Option<u64> {
        self.base_fee_per_gas
    }

    fn blob_gas_used(&self) -> Option<u64> {
        self.blob_gas_used
    }

    fn excess_blob_gas(&self) -> Option<u64> {
        self.excess_blob_gas
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.parent_beacon_block_root
    }

    fn requests_hash(&self) -> Option<B256> {
        self.requests_hash
    }

    fn extra_data(&self) -> &Bytes {
        &self.extra_data
    }
}

impl reth_primitives_traits::BlockHeader for GnosisHeader {}

impl InMemorySize for GnosisHeader {
    fn size(&self) -> usize {
        let mut size = self.size_of();
        if self.is_post_merge() {
            size += mem::size_of::<B64>() + mem::size_of::<u64>();
        } else {
            debug!("Pre-merge header detected");
            size += mem::size_of::<Option<u64>>()
                + self.aura_seal.as_ref().map_or(0, |seal| seal.len());
        }
        size
    }
}

impl Encodable for GnosisHeader {
    fn encode(&self, out: &mut dyn BufMut) {
        let list_header = alloy_rlp::Header {
            list: true,
            payload_length: self.header_payload_length(),
        };
        list_header.encode(out);
        self.parent_hash.encode(out);
        self.ommers_hash.encode(out);
        self.beneficiary.encode(out);
        self.state_root.encode(out);
        self.transactions_root.encode(out);
        self.receipts_root.encode(out);
        self.logs_bloom.encode(out);
        self.difficulty.encode(out);
        U256::from(self.number).encode(out);
        U256::from(self.gas_limit).encode(out);
        U256::from(self.gas_used).encode(out);
        self.timestamp.encode(out);
        self.extra_data.encode(out);
        if self.is_post_merge() {
            self.mix_hash.unwrap().encode(out);
            self.nonce.unwrap().encode(out);
        } else {
            self.aura_step.unwrap().encode(out);
            self.aura_seal.as_ref().unwrap().encode(out);
        }

        // Encode all the fork specific fields
        if let Some(ref base_fee) = self.base_fee_per_gas {
            U256::from(*base_fee).encode(out);
        }

        if let Some(ref root) = self.withdrawals_root {
            root.encode(out);
        }

        if let Some(ref blob_gas_used) = self.blob_gas_used {
            U256::from(*blob_gas_used).encode(out);
        }

        if let Some(ref excess_blob_gas) = self.excess_blob_gas {
            U256::from(*excess_blob_gas).encode(out);
        }

        if let Some(ref parent_beacon_block_root) = self.parent_beacon_block_root {
            parent_beacon_block_root.encode(out);
        }

        if let Some(ref requests_hash) = self.requests_hash {
            requests_hash.encode(out);
        }
    }

    fn length(&self) -> usize {
        let mut length = 0;
        length += self.header_payload_length();
        length += length_of_length(length);
        length
    }
}

impl Decodable for GnosisHeader {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let rlp_head = alloy_rlp::Header::decode(buf)?;
        if !rlp_head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        let started_len = buf.len();
        let mut this = Self {
            parent_hash: Decodable::decode(buf)?,
            ommers_hash: Decodable::decode(buf)?,
            beneficiary: Decodable::decode(buf)?,
            state_root: Decodable::decode(buf)?,
            transactions_root: Decodable::decode(buf)?,
            receipts_root: Decodable::decode(buf)?,
            logs_bloom: Decodable::decode(buf)?,
            difficulty: Decodable::decode(buf)?,
            number: u64::decode(buf)?,
            gas_limit: u64::decode(buf)?,
            gas_used: u64::decode(buf)?,
            timestamp: Decodable::decode(buf)?,
            extra_data: Decodable::decode(buf)?,
            // mix_hash: Some(Decodable::decode(buf)?),
            // nonce: Some(B64::decode(buf)?),
            mix_hash: None,
            nonce: None,
            aura_step: None,
            aura_seal: None,

            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        };

        let temp_buf = buf.to_owned();
        let mut temp_buf = &temp_buf[..];

        // Peek at the next element to determine if it's post-merge or pre-merge
        let next_head = alloy_rlp::Header::decode(&mut temp_buf)?; // This advances the buffer

        let is_post_merge = next_head.payload_length == 32; // 32 bytes for mix_hash

        if is_post_merge {
            // Next field is mix_hash (32 bytes)
            this.mix_hash = Some(Decodable::decode(buf)?);
            this.nonce = Some(B64::decode(buf)?);
        } else {
            // Next field is AuRaStep (u64, usually 8 bytes)
            this.aura_step = Some(U256::decode(buf)?);

            // Next field is AuRaSeal (variable length)
            let aura_seal_bytes = Bytes::decode(buf)?;
            this.aura_seal = Some(
                FixedBytes::<65>::try_from(aura_seal_bytes.as_ref()).map_err(|_| {
                    alloy_rlp::Error::Custom("Failed to decode aura_seal as FixedBytes<65>")
                })?,
            );
        }

        if started_len - buf.len() < rlp_head.payload_length {
            this.base_fee_per_gas = Some(u64::decode(buf)?);
        }

        // Withdrawals root for post-shanghai headers
        if started_len - buf.len() < rlp_head.payload_length {
            this.withdrawals_root = Some(Decodable::decode(buf)?);
        }

        // Blob gas used and excess blob gas for post-cancun headers
        if started_len - buf.len() < rlp_head.payload_length {
            this.blob_gas_used = Some(u64::decode(buf)?);
        }

        if started_len - buf.len() < rlp_head.payload_length {
            this.excess_blob_gas = Some(u64::decode(buf)?);
        }

        // Decode parent beacon block root.
        if started_len - buf.len() < rlp_head.payload_length {
            this.parent_beacon_block_root = Some(B256::decode(buf)?);
        }

        // Decode requests hash.
        if started_len - buf.len() < rlp_head.payload_length {
            this.requests_hash = Some(B256::decode(buf)?);
        }

        let consumed = started_len - buf.len();
        if consumed != rlp_head.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: rlp_head.payload_length,
                got: consumed,
            });
        }
        Ok(this)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize, Compact)]
struct CompactHeader {
    parent_hash: B256,
    ommers_hash: B256,
    beneficiary: Address,
    state_root: B256,
    transactions_root: B256,
    receipts_root: B256,
    withdrawals_root: Option<B256>,
    logs_bloom: Bloom,
    difficulty: U256,
    number: BlockNumber,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    mix_hash: Option<B256>,
    nonce: Option<u64>,
    aura_step: Option<U256>,
    aura_seal: Option<FixedBytes<65>>,
    base_fee_per_gas: Option<u64>,
    blob_gas_used: Option<u64>,
    excess_blob_gas: Option<u64>,
    parent_beacon_block_root: Option<B256>,
    requests_hash: Option<B256>,
    extra_data: Bytes,
}

impl reth_codecs::Compact for GnosisHeader {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::bytes::BufMut + AsMut<[u8]>,
    {
        let header = CompactHeader {
            parent_hash: self.parent_hash,
            ommers_hash: self.ommers_hash,
            beneficiary: self.beneficiary,
            state_root: self.state_root,
            transactions_root: self.transactions_root,
            receipts_root: self.receipts_root,
            withdrawals_root: self.withdrawals_root,
            logs_bloom: self.logs_bloom,
            difficulty: self.difficulty,
            number: self.number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            mix_hash: self.mix_hash,
            nonce: if let Some(n) = self.nonce {
                Some(n.into())
            } else {
                None
            },
            aura_step: self.aura_step,
            aura_seal: self.aura_seal,
            base_fee_per_gas: self.base_fee_per_gas,
            blob_gas_used: self.blob_gas_used,
            excess_blob_gas: self.excess_blob_gas,
            parent_beacon_block_root: self.parent_beacon_block_root,
            requests_hash: self.requests_hash,
            extra_data: self.extra_data.clone(),
        };
        header.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (header, _) = CompactHeader::from_compact(buf, len);
        let alloy_header = Self {
            parent_hash: header.parent_hash,
            ommers_hash: header.ommers_hash,
            beneficiary: header.beneficiary,
            state_root: header.state_root,
            transactions_root: header.transactions_root,
            receipts_root: header.receipts_root,
            withdrawals_root: header.withdrawals_root,
            logs_bloom: header.logs_bloom,
            difficulty: header.difficulty,
            number: header.number,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            timestamp: header.timestamp,
            mix_hash: header.mix_hash,
            nonce: if let Some(n) = header.nonce {
                Some(n.into())
            } else {
                None
            },
            aura_step: header.aura_step,
            aura_seal: header.aura_seal,
            base_fee_per_gas: header.base_fee_per_gas,
            blob_gas_used: header.blob_gas_used,
            excess_blob_gas: header.excess_blob_gas,
            parent_beacon_block_root: header.parent_beacon_block_root,
            requests_hash: header.requests_hash,
            extra_data: header.extra_data,
        };
        (alloy_header, buf)
    }
}

// tests
#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, b256};

    fn get_sample_pre_merge_header() -> GnosisHeader {
        let sample_aura_seal: FixedBytes<65> = FixedBytes::from_slice(
            b"sample_aura_seal_000000000000000000000000000000000000000000000000",
        );
        GnosisHeader {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::default(),
            difficulty: U256::from(1000),
            number: 1,
            gas_limit: 1000000,
            gas_used: 500000,
            timestamp: 1622547800,
            extra_data: Bytes::from_static(b"extra data"),
            mix_hash: None,
            nonce: None,
            aura_step: Some(U256::from(1637394693478219i128)),
            aura_seal: Some(sample_aura_seal),
            base_fee_per_gas: Some(73468),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        }
    }

    fn get_sample_post_merge_header() -> GnosisHeader {
        GnosisHeader {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::default(),
            difficulty: U256::from(10000000),
            number: 1,
            gas_limit: 1000000,
            gas_used: 500000,
            timestamp: 1622547800,
            extra_data: Bytes::from_static(b"extra data"),
            mix_hash: Some(b256!(
                "661da523f3e44725f3a1cee38183d35424155a05674609a9f6ed81243adf9e26"
            )),
            nonce: Some(B64::from(938473940u64)),
            aura_step: None,
            aura_seal: None,
            base_fee_per_gas: Some(100),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        }
    }

    #[test]
    fn test_pre_merge_header_size() {
        let header = get_sample_pre_merge_header();
        println!("Header: {:?}", &header);
        assert_eq!(header.size(), 802); // Adjusted size based on fields
    }

    #[test]
    fn test_post_merge_header_size() {
        let header = get_sample_post_merge_header();
        assert_eq!(header.size(), 737); // Adjusted size based on fields
    }

    #[test]
    fn test_pre_merge_encode_decode() {
        // let header = get_sample_post_merge_header();
        let header = get_sample_pre_merge_header();
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert!(
            !buf.is_empty(),
            "Header encoding should produce non-empty output"
        );
        assert_eq!(
            buf.len(),
            header.length(),
            "Encoded length should match expected length"
        );

        // Decode the header back
        let mut buf_slice = &buf[..];
        let decoded_header = GnosisHeader::decode(&mut buf_slice).expect("Failed to decode header");
        println!("Decoded Header: {:?}", decoded_header);
        assert_eq!(
            decoded_header, header,
            "Decoded header should match original header"
        );
        // panic!("check")
    }

    #[test]
    fn test_post_merge_encode_decode() {
        let header = get_sample_post_merge_header();
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert!(
            !buf.is_empty(),
            "Header encoding should produce non-empty output"
        );
        assert_eq!(
            buf.len(),
            header.length(),
            "Encoded length should match expected length"
        );

        // Decode the header back
        let mut buf_slice = &buf[..];
        let decoded_header = GnosisHeader::decode(&mut buf_slice).expect("Failed to decode header");
        println!("Decoded Header: {:?}", decoded_header);
        assert_eq!(
            decoded_header, header,
            "Decoded header should match original header"
        );
    }

    #[test]
    fn test_pre_merge_header_compact_decompact() {
        let header = get_sample_pre_merge_header();
        let mut buf = Vec::new();

        let compact_len = header.to_compact(&mut buf);
        assert!(
            compact_len > 0,
            "Compact encoding should produce non-empty output"
        );

        // Decode the header back
        let (decoded_header, _) = GnosisHeader::from_compact(&buf, compact_len);
        println!("Decoded Header: {:?}", decoded_header);
        assert_eq!(
            decoded_header, header,
            "Decoded header should match original header"
        );
    }

    #[test]
    fn test_post_merge_header_compact_decompact() {
        let header = get_sample_post_merge_header();
        let mut buf = Vec::new();

        let compact_len = header.to_compact(&mut buf);
        assert!(
            compact_len > 0,
            "Compact encoding should produce non-empty output"
        );

        // Decode the header back
        let (decoded_header, _) = GnosisHeader::from_compact(&buf, compact_len);
        println!("Decoded Header: {:?}", decoded_header);
        assert_eq!(
            decoded_header, header,
            "Decoded header should match original header"
        );
    }
}
