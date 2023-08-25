use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, AssignedCell, Value},
    plonk::{Circuit, Advice, Instance, Column, ConstraintSystem, Error},
    halo2curves::pasta::{Fp, pallas},
};
use halo2_gadgets::{
    poseidon::{
        Pow5Chip as PoseidonChip,
        Pow5Config as PoseidonConfig,
        Hash as PoseidonHash,
        primitives::{P128Pow5T3, ConstantLength},
    },
    sinsemilla::{merkle::{*, chip::MerkleConfig}, HashDomain},
    utilities::UtilitiesInstructions,
};

mod gadgets;

pub const MERKLE_DEPTH: usize = 20;

// Absolute offsets for public inputs.
const COMMITMENT: usize = 0;
const NULLIFIER_HASH: usize = 1;
const ROOT: usize = 2;

pub const WIDTH: usize = 3;
pub const RATE: usize = 2;

#[derive(Clone, Debug)]
pub struct Config {
    advices: [Column<Advice>; 4],
    instance: Column<Instance>,
    poseidon_config: PoseidonConfig<pallas::Base, WIDTH, RATE>,
}

#[derive(Debug, Default)]
pub struct TornadoCircuit {
    secret: Value<Fp>,
    nullifier: Value<Fp>,
    // poseidon_bits: Option<[Fp; MERKLE_DEPTH]>,
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
        // to_hash: &str,
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
            meta.advice_column(),
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

        Config {
            advices,
            instance,
            poseidon_config,
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

        println!("{:?}", commitment.value());
        self.expose_public(layouter.namespace(|| "expose commitment"), config.instance, commitment, COMMITMENT)?;

        Ok({})
    }
}

#[cfg(test)]
mod tests {
    use super::TornadoCircuit;
    use halo2_proofs::{dev::MockProver, halo2curves::pasta::Fp, circuit::Value};
    use halo2_gadgets::{
        poseidon::{
            Pow5Chip as PoseidonChip,
            Pow5Config as PoseidonConfig,
            Hash as PoseidonHash,
            primitives::{P128Pow5T3, ConstantLength},
        },
        sinsemilla::{merkle::{*, chip::MerkleConfig}, HashDomain},
    };

    #[test]
    fn commitment() {
        let k = 10;

        let secret = Fp::from(2);
        let nullifier = Fp::from(3);
        // let external_nullifier = Fp::from(5);
        // let path = [Fp::from(1), Fp::from(1), Fp::from(1), Fp::from(1)];
        // let position_bits = [Fp::from(0), Fp::from(0), Fp::from(0), Fp::from(0)];

        let message = [secret, nullifier];
        // TODO: calculate hash
        // let commitment = ...
        
        let circuit = TornadoCircuit {
            secret: Value::known(secret),
            nullifier: Value::known(nullifier),
        };

        let public_inputs = vec![
            Fp::from(6), // TODO: replace it to hash
        ];

        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert!(prover.verify().is_err()); // TODO: pass it
    }
}

fn main() {}