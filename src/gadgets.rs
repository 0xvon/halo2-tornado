use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, AssignedCell, Value},
    plonk::{Circuit, Advice, Instance, Column, ConstraintSystem, Error},
    halo2curves::pasta::{Fp, pallas},
};
use halo2_gadgets::{
    poseidon::{
        Pow5Chip as PoseidonChip,
        Pow5Config as PoseidonConfig,
        PoseidonInstructions,
        Hash as PoseidonHash,
        primitives::{P128Pow5T3, ConstantLength},
    },
    sinsemilla::{merkle::{*, chip::MerkleConfig}, HashDomain},
    utilities::UtilitiesInstructions,
};

use crate::{WIDTH, RATE};

impl super::Config {
    // pub(super) fn construct_merkle_chip(&self) -> MerkleChip {
    //     MerkleChip::construct(self.merkle_config.clone())
    // }

    pub(super) fn construct_poseidon_chip(&self) -> PoseidonChip<Fp, WIDTH, RATE> {
        PoseidonChip::construct(self.poseidon_config.clone())
    }
}
