use asterism_core::network::{ElementsNetworkId, NetworkType};
use elements::AddressParams;

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

    /// Returns the [`lwk_wollet::ElementsNetwork`]-compatible network
    /// identifier.
    ///
    /// LWK uses the same enum shape but its own type. This method returns
    /// the `elements::bitcoin::Network` value that LWK's `WolletBuilder`
    /// and `EsploraClient` expect.
    #[must_use]
    pub fn lwk_network(&self) -> elements::bitcoin::Network {
        match self {
            Self::Liquid => elements::bitcoin::Network::Bitcoin,
            Self::LiquidTestnet => elements::bitcoin::Network::Testnet,
            Self::ElementsRegtest => elements::bitcoin::Network::Regtest,
        }
    }

    /// Convert to the lightweight [`ElementsNetworkId`] carried by
    /// `asterism-core`.
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
