use halo2_proofs::halo2curves::pasta::Fp;
use halo2_gadgets::{
    poseidon::Pow5Chip as PoseidonChip,
    sinsemilla::merkle::chip::MerkleChip,
};

use crate::{WIDTH, RATE};
use super::{TornadoCommitDomain, TornadoFixedPoint, TornadoHashDomain};

impl super::Config {
    pub(super) fn construct_merkle_chip(&self) -> MerkleChip<TornadoHashDomain, TornadoCommitDomain, TornadoFixedPoint> {
        MerkleChip::<TornadoHashDomain, TornadoCommitDomain, TornadoFixedPoint>::construct(self.merkle_config.clone())
    }

    pub(super) fn construct_poseidon_chip(&self) -> PoseidonChip<Fp, WIDTH, RATE> {
        PoseidonChip::construct(self.poseidon_config.clone())
    }
}
