# Halo2 Tornado

The Tornado's Circuit Implementation with PSE/Halo2.

#### Disclaimer

DO NOT USE THIS LIBRARY IN PRODUCTION. At this point, this is under development. It has known and unknown bugs and security flaws.

#### Features

This is the Halo2 Circuit of [tornado-core](https://github.com/tornadocash/tornado-core/blob/master/circuits/withdraw.circom).

- The unnecessary computations are removed here. 
- Using Poseidon Hash instead of Pedersen Commitment.

<br>

# Get Started

#### Install Rust

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### Run

```
$ cargo run
```

#### Test

```
$ RUST_LOG=all cargo test -r -- --nocapture
```