use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, AssignedCell, Value},
    plonk::{Circuit, Advice, Instance, Column, ConstraintSystem, Error},
    halo2curves::{pasta::{Fp, pallas}, group::{Group, Curve}},
};
use halo2_gadgets::{
    poseidon::{
        Pow5Chip as PoseidonChip,
        Pow5Config as PoseidonConfig,
        Hash as PoseidonHash,
        primitives::{P128Pow5T3, ConstantLength},
    },
    sinsemilla::{
        merkle::{chip::{MerkleConfig, MerkleChip}, MerklePath},
        CommitDomains, HashDomains, chip::SinsemillaChip,
    },
    utilities::{UtilitiesInstructions, lookup_range_check::LookupRangeCheckConfig},
    ecc::FixedPoints,
};

mod gadgets;

pub const MERKLE_DEPTH: usize = 4;

// Absolute offsets for public inputs.
const COMMITMENT: usize = 0;
const ROOT: usize = 1;

pub const WIDTH: usize = 3;
pub const RATE: usize = 2;

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

#[derive(Clone, Debug)]
pub struct Config {
    advices: [Column<Advice>; 5],
    instance: Column<Instance>,
    poseidon_config: PoseidonConfig<pallas::Base, WIDTH, RATE>,
    merkle_config: MerkleConfig<TornadoHashDomain, TornadoCommitDomain, TornadoFixedPoint>,
}

#[derive(Debug, Default)]
pub struct TornadoCircuit {
    secret: Value<Fp>,
    nullifier: Value<Fp>,
    position_bits: Value<u32>,
    path: Value<[Fp; MERKLE_DEPTH]>,
}

impl UtilitiesInstructions<pallas::Base> for TornadoCircuit {
    type Var = AssignedCell<pallas::Base, pallas::Base>;
}

impl TornadoCircuit {
    fn hash(
        &self,
        config: Config,
        mut layouter: impl Layouter<Fp>,
        message: [AssignedCell<Fp, Fp>; 2],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let config = config.clone();
        
        let poseidon_chip = config.construct_poseidon_chip();

        let poseidon_hasher: PoseidonHash
        <
            Fp,
            PoseidonChip<Fp, WIDTH, RATE>,
            P128Pow5T3,
            ConstantLength<2_usize>,
            3_usize,
            2_usize
        >
            = PoseidonHash::init(poseidon_chip, layouter.namespace(|| "init hasher"))?;

        
        return poseidon_hasher.hash(
            layouter.namespace(|| "hash"),
            message
        );
    }

    fn calculate_root(
        &self,
        config: Config,
        mut layouter: impl Layouter<Fp>,
        commitment: AssignedCell<Fp, Fp>,
        position_bits: Value<u32>,
        path: Value<[pallas::Base; MERKLE_DEPTH]>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let config = config.clone();

        let merkle_chip = config.construct_merkle_chip();

        let merkle_inputs: MerklePath
        <
            pallas::Affine,
            MerkleChip<TornadoHashDomain, TornadoCommitDomain, TornadoFixedPoint>,
            MERKLE_DEPTH, 10, 253, 1,
        > = MerklePath::construct(
            [merkle_chip],
            TornadoHashDomain,
            position_bits,
            path
        );

        return merkle_inputs.calculate_root(
            layouter.namespace(|| "merkle root"),
            commitment,
        );
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        column: Column<Instance>,
        cell: AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), column, row)
    }
}

impl Circuit<pallas::Base> for TornadoCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(), // For Poseidon
            meta.advice_column(), // For Merkle
        ];

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        for advice in advices.iter() {
            meta.enable_equality(advice.clone());
        }

        let rc_a = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_b = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        meta.enable_constant(rc_b[0]);
        let poseidon_config = PoseidonChip::configure::<P128Pow5T3>(meta, advices[0..3].try_into().unwrap(), advices[3], rc_a, rc_b);

        // Shared fixed column for loading constants
        let merkle_constants = meta.fixed_column();
        meta.enable_constant(merkle_constants);

        let merkle_fixed_y_q = meta.fixed_column();

        // Fixed columns for the Sinsemilla generator lookup table
        let merkle_lookup = (
            meta.lookup_table_column(),
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        let range_check = LookupRangeCheckConfig::configure(meta, advices[4], merkle_lookup.0);

        let sinsemilla_config = SinsemillaChip::configure(
            meta,
            advices[..5].try_into().unwrap(),
            advices[2],
            merkle_fixed_y_q,
            merkle_lookup,
            range_check,
        );
        let merkle_config = MerkleChip::configure(meta, sinsemilla_config);

        Config {
            advices,
            instance,
            poseidon_config,
            merkle_config,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<pallas::Base>) -> Result<(), Error> {
        let secret = self.load_private(
            layouter.namespace(|| "witness identity_trapdoor"),
            config.advices[0],
            self.secret,
        )?;

        let nullifier = self.load_private(
            layouter.namespace(|| "witness identity_trapdoor"),
            config.advices[0],
            self.nullifier,
        )?;

        let secret_message = [secret, nullifier];
        let commitment = self.hash(
            config.clone(),
            layouter.namespace(|| "hash to commitment"),
            secret_message,
        )?;

        let root = self.calculate_root(
            config.clone(),
            layouter.namespace(|| "root to commitment"),
            commitment.clone(),
            self.position_bits,
            self.path,
        )?;

        // println!("commitment: {:?}, root: {:?}", commitment.value(), root.value());
        self.expose_public(layouter.namespace(|| "expose commitment"), config.instance, commitment.clone(), COMMITMENT)?;
        self.expose_public(layouter.namespace(|| "expose root"), config.instance, root.clone(), ROOT)?;

        Ok({})
    }
}

#[cfg(test)]
mod tests {
    use super::TornadoCircuit;
    use halo2_proofs::{dev::MockProver, halo2curves::pasta::Fp, circuit::Value};

    #[test]
    fn commitment() {
        let k = 10;

        let secret = Fp::from(2);
        let nullifier = Fp::from(3);
        let path = [
            Fp::from(1), Fp::from(1), Fp::from(1), Fp::from(1), 
        ];
        let position_bits: u32 = 1;
        
        let circuit = TornadoCircuit {
            secret: Value::known(secret),
            nullifier: Value::known(nullifier),
            path: Value::known(path),
            position_bits: Value::known(position_bits),
        };

        let public_inputs = vec![
            Fp::from_raw([
                0x92c1f7b1649c6bbf,
                0xa227de40a263afa7,
                0xe727c638157add9c,
                0x1df874f19cd1afa3,
            ]),
            Fp::from_raw([
                0x3058c942b6150b15,
                0x369f22098cb08f84,
                0xd4e309a93493cd14,
                0x3e0dd91d7883e6b1,
            ]),
        ];

        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()))
    }
}

fn main() {}