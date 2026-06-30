use elements::AddressParams;
use emvault_core::network::{ElementsNetworkId, NetworkType};

/// Elements/Liquid network with full parameters needed by LWK and address
/// derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ElementsNetwork {
    /// Liquid mainnet.
    Liquid,
    /// Liquid testnet.
    LiquidTestnet,
    /// Local Elements regtest.
    ElementsRegtest,
}

impl ElementsNetwork {
    /// Returns the [`AddressParams`] for this network, used by
    /// `elements_miniscript::ConfidentialDescriptor::address`.
    #[must_use]
    pub fn address_params(&self) -> &'static AddressParams {
        match self {
            Self::Liquid => &AddressParams::LIQUID,
            Self::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
            Self::ElementsRegtest => &AddressParams::ELEMENTS,
        }
    }

    /// Returns the [`lwk_wollet::Network`] value that LWK's `WolletBuilder`
    /// and blockchain clients expect.
    ///
    /// `ElementsRegtest` maps to `Network::default_regtest()` (LWK's *default*
    /// regtest parameters). A real `elementsd` regtest node usually has a
    /// different policy asset and genesis hash; in that case construct the
    /// network from the node's values via [`Self::custom_regtest`] and use the
    /// `*_with_lwk` constructors so blinding, fee accounting, and the signing
    /// genesis all match the node.
    #[must_use]
    pub fn to_lwk(&self) -> lwk_wollet::Network {
        match self {
            Self::Liquid => lwk_wollet::Network::Liquid,
            Self::LiquidTestnet => lwk_wollet::Network::TestnetLiquid,
            Self::ElementsRegtest => lwk_wollet::Network::default_regtest(),
        }
    }

    /// Build an [`lwk_wollet::Network`] for a custom Elements regtest using the
    /// node's actual policy (L-BTC) asset and genesis block hash.
    ///
    /// These differ per node configuration, so the consuming application should
    /// source them from the node (`getsidechaininfo.pegged_asset` and
    /// `getblockhash 0`).
    #[must_use]
    pub fn custom_regtest(
        policy_asset: elements::AssetId,
        genesis_hash: elements::BlockHash,
    ) -> lwk_wollet::Network {
        let params = lwk_common::ElementsParamsBuilder::new()
            .with_policy_asset(policy_asset)
            .with_genesis_hash(genesis_hash)
            .build()
            .expect("valid Elements params");
        lwk_wollet::Network::CustomElements(params)
    }

    /// Convert to the lightweight [`ElementsNetworkId`] carried by
    /// `emvault-core`.
    #[must_use]
    pub fn to_core_id(self) -> ElementsNetworkId {
        match self {
            Self::Liquid => ElementsNetworkId::Liquid,
            Self::LiquidTestnet => ElementsNetworkId::LiquidTestnet,
            Self::ElementsRegtest => ElementsNetworkId::ElementsRegtest,
        }
    }
}

impl From<ElementsNetworkId> for ElementsNetwork {
    fn from(id: ElementsNetworkId) -> Self {
        match id {
            ElementsNetworkId::Liquid => Self::Liquid,
            ElementsNetworkId::LiquidTestnet => Self::LiquidTestnet,
            ElementsNetworkId::ElementsRegtest => Self::ElementsRegtest,
        }
    }
}

impl From<ElementsNetwork> for ElementsNetworkId {
    fn from(n: ElementsNetwork) -> Self {
        n.to_core_id()
    }
}

impl From<ElementsNetwork> for NetworkType {
    fn from(n: ElementsNetwork) -> Self {
        NetworkType::Elements(n.to_core_id())
    }
}

impl std::fmt::Display for ElementsNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Liquid => "liquid",
            Self::LiquidTestnet => "liquidtestnet",
            Self::ElementsRegtest => "elementsregtest",
        };
        f.write_str(s)
    }
}
