use halo2_gadgets::{
    poseidon::Pow5Chip as PoseidonChip,
    sinsemilla::merkle::chip::MerkleChip,
    sinsemilla::{CommitDomains, HashDomains},
    ecc::FixedPoints,
};
use halo2_proofs::halo2curves::{
    pasta::{Fp, pallas},
    group::{Group, Curve},
};

use crate::{WIDTH, RATE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TornadoHashDomain;
#[allow(non_snake_case)]
impl HashDomains<pallas::Affine> for TornadoHashDomain {
    fn Q(&self) -> pallas::Affine {
        pallas::Point::generator().to_affine() // ???
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TornadoFixedPoint;
impl FixedPoints<pallas::Affine> for TornadoFixedPoint {
    type FullScalar = pallas::Affine;
    type ShortScalar = pallas::Affine;
    type Base = pallas::Affine;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TornadoCommitDomain;
impl CommitDomains<pallas::Affine, TornadoFixedPoint, TornadoHashDomain> for TornadoCommitDomain {
    fn r(&self) -> <TornadoFixedPoint as FixedPoints<pallas::Affine>>::FullScalar {
        pallas::Point::generator().to_affine()
    }

    fn hash_domain(&self) -> TornadoHashDomain {
        TornadoHashDomain
    }
}

impl super::Config {
    pub(super) fn construct_poseidon_chip(&self) -> PoseidonChip<Fp, WIDTH, RATE> {
        PoseidonChip::construct(self.poseidon_config.clone())
    }
    
    pub(super) fn construct_merkle_chip(&self) -> MerkleChip<TornadoHashDomain, TornadoCommitDomain, TornadoFixedPoint> {
        MerkleChip::<TornadoHashDomain, TornadoCommitDomain, TornadoFixedPoint>::construct(self.merkle_config.clone())
    }
}
